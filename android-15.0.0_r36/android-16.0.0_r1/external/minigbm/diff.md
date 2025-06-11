```diff
diff --git a/Android.bp b/Android.bp
index 57f44d5..d044e7d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -50,6 +50,7 @@ filegroup {
         "virtgpu.c",
         "virtgpu_cross_domain.c",
         "virtgpu_virgl.c",
+        "xe.c",
     ],
 }
 
@@ -58,8 +59,8 @@ filegroup {
 
     srcs: [
         "cros_gralloc/cros_gralloc_buffer.cc",
-        "cros_gralloc/cros_gralloc_helpers.cc",
         "cros_gralloc/cros_gralloc_driver.cc",
+        "cros_gralloc/cros_gralloc_helpers.cc",
     ],
 }
 
@@ -68,19 +69,39 @@ filegroup {
     srcs: ["cros_gralloc/gralloc0/gralloc0.cc"],
 }
 
+generic_cflags = ["-DHAS_DMABUF_SYSTEM_HEAP"]
+intel_cflags = [
+    "-DDRV_I915",
+    "-DDRV_XE",
+]
+meson_cflags = ["-DDRV_MESON"]
+msm_cflags = [
+    "-DDRV_MSM",
+    "-DHAS_DMABUF_SYSTEM_HEAP",
+    "-DQCOM_DISABLE_COMPRESSED_NV12",
+]
+arcvm_cflags = ["-DVIRTIO_GPU_NEXT"]
+
 cc_defaults {
     name: "minigbm_defaults",
 
     cflags: [
-        "-D_GNU_SOURCE=1",
         "-D_FILE_OFFSET_BITS=64",
+        "-D_GNU_SOURCE=1",
         "-Wall",
-        "-Wsign-compare",
-        "-Wpointer-arith",
-        "-Wcast-qual",
         "-Wcast-align",
+        "-Wcast-qual",
         "-Wno-unused-parameter",
-    ],
+        "-Wpointer-arith",
+        "-Wsign-compare",
+    ] + select(soong_config_variable("minigbm", "platform"), {
+        "generic": generic_cflags,
+        "intel": intel_cflags,
+        "meson": meson_cflags,
+        "msm": msm_cflags,
+        "arcvm": arcvm_cflags,
+        default: [],
+    }),
 
     product_variables: {
         platform_sdk_version: {
@@ -117,9 +138,9 @@ cc_defaults {
         "libdmabufheap",
         "libdrm",
         "libgralloctypes",
+        "liblog",
         "libnativewindow",
         "libsync",
-        "liblog",
     ],
 }
 
@@ -142,20 +163,11 @@ cc_defaults {
     srcs: [":minigbm_gralloc0_files"],
 }
 
-generic_cflags = ["-DHAS_DMABUF_SYSTEM_HEAP"]
-intel_cflags = ["-DDRV_I915"]
-meson_cflags = ["-DDRV_MESON"]
-msm_cflags = [
-    "-DDRV_MSM",
-    "-DQCOM_DISABLE_COMPRESSED_NV12",
-    "-DHAS_DMABUF_SYSTEM_HEAP",
-]
-arcvm_cflags = ["-DVIRTIO_GPU_NEXT"]
-
 cc_library {
     name: "libgbm",
     defaults: ["minigbm_defaults"],
     host_supported: true,
+    min_sdk_version: "34",
 
     srcs: [
         ":minigbm_core_files",
@@ -164,15 +176,6 @@ cc_library {
         "minigbm_helpers.c",
     ],
 
-    cflags: select(soong_config_variable("minigbm", "platform"), {
-        "generic": generic_cflags,
-        "intel": intel_cflags,
-        "meson": meson_cflags,
-        "msm": msm_cflags,
-        "arcvm": arcvm_cflags,
-        default: [],
-    }),
-
     target: {
         host: {
             // Avoid linking to another host copy of libdrm; this library will cause
@@ -192,8 +195,8 @@ cc_library {
         },
     },
     apex_available: [
-        "//apex_available:platform",
         "//apex_available:anyapex",
+        "//apex_available:platform",
     ],
     vendor_available: true,
     product_available: true,
@@ -208,10 +211,10 @@ rust_bindgen {
     wrapper_src: "rust/gbm_wrapper.h",
     source_stem: "bindings",
     bindgen_flags: [
-        "--blocklist-type=__BINDGEN_TMP_.*",
-        "--allowlist-type=^gbm_.*$",
         "--allowlist-function=^gbm_.*$",
+        "--allowlist-type=^gbm_.*$",
         "--allowlist-var=GBM_.*|gbm_.*$",
+        "--blocklist-type=__BINDGEN_TMP_.*",
         "--constified-enum-module=^gbm_.*$",
     ],
     shared_libs: ["libgbm"],
@@ -224,6 +227,7 @@ rust_bindgen {
     ],
     visibility: [
         "//external/rust/android-crates-io/crates/gbm",
+        "//system/cros-codecs",
     ],
 }
 
diff --git a/METADATA b/METADATA
index 033bcb8..cfa2c99 100644
--- a/METADATA
+++ b/METADATA
@@ -1,16 +1,20 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/minigbm
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
 name: "minigbm"
 description: ""
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
+    year: 2025
     month: 3
-    day: 12
+    day: 20
   }
   homepage: "https://www.chromium.org/"
   identifier {
     type: "Git"
     value: "https://chromium.googlesource.com/chromiumos/platform/minigbm/"
-    version: "40b28f098a29589b3f72de1ba6753d46a616c48b"
+    version: "3dd534cca22443d6ed2c7c0e2929a0a47c2a524c"
   }
 }
diff --git a/Makefile b/Makefile
index 90805dd..33a40ff 100644
--- a/Makefile
+++ b/Makefile
@@ -20,7 +20,7 @@ ifdef DRV_AMDGPU
 	CFLAGS += $(shell $(PKG_CONFIG) --cflags libdrm_amdgpu)
 	LDLIBS += -ldrm_amdgpu -ldl
 endif
-ifdef DRV_I915
+ifeq ($(filter 1,$(DRV_I915) $(DRV_XE)),)
 	CFLAGS += $(shell $(PKG_CONFIG) --cflags libdrm_intel)
 endif
 ifdef DRV_MESON
diff --git a/OWNERS b/OWNERS
index 3a6b617..ae47cc1 100644
--- a/OWNERS
+++ b/OWNERS
@@ -4,7 +4,6 @@ dbehr@chromium.org
 ddavenport@chromium.org
 gurchetansingh@chromium.org
 hiroh@chromium.org
-marcheu@chromium.org
 mcasas@chromium.org
 niwa@chromium.org
 olv@google.com
diff --git a/OWNERS.android b/OWNERS.android
index be55e00..54e65dc 100644
--- a/OWNERS.android
+++ b/OWNERS.android
@@ -1,2 +1,3 @@
 adelva@google.com
 natsu@google.com
+include platform/system/core:main:/janitors/OWNERS
diff --git a/cros_gralloc/cros_gralloc_helpers.cc b/cros_gralloc/cros_gralloc_helpers.cc
index 945552c..9495778 100644
--- a/cros_gralloc/cros_gralloc_helpers.cc
+++ b/cros_gralloc/cros_gralloc_helpers.cc
@@ -128,7 +128,7 @@ uint64_t cros_gralloc_convert_usage(uint64_t usage)
 	handle_usage(&usage, GRALLOC_USAGE_EXTERNAL_DISP, &use_flags, BO_USE_NONE);
 	/* Map PROTECTED to linear until real HW protection is available on Android. */
 	handle_usage(&usage, GRALLOC_USAGE_PROTECTED, &use_flags, BO_USE_LINEAR);
-	handle_usage(&usage, GRALLOC_USAGE_CURSOR, &use_flags, BO_USE_NONE);
+	handle_usage(&usage, GRALLOC_USAGE_CURSOR, &use_flags, BO_USE_CURSOR);
 	/* HACK: See b/30054495 for BO_USE_SW_READ_OFTEN. */
 	handle_usage(&usage, GRALLOC_USAGE_HW_VIDEO_ENCODER, &use_flags,
 		     BO_USE_HW_VIDEO_ENCODER | BO_USE_SW_READ_OFTEN);
diff --git a/drv.c b/drv.c
index 7fd2250..c1f9c4f 100644
--- a/drv.c
+++ b/drv.c
@@ -34,6 +34,9 @@ extern const struct backend backend_amdgpu;
 #ifdef DRV_I915
 extern const struct backend backend_i915;
 #endif
+#ifdef DRV_XE
+extern const struct backend backend_xe;
+#endif
 #ifdef DRV_MSM
 extern const struct backend backend_msm;
 #endif
@@ -70,6 +73,9 @@ static const struct backend *drv_backend_list[] = {
 #endif
 #ifdef DRV_VC4
 	&backend_vc4,
+#endif
+#ifdef DRV_XE
+	&backend_xe,
 #endif
 	&backend_evdi,	    &backend_komeda,	&backend_marvell, &backend_mediatek,
 	&backend_meson,	    &backend_nouveau,	&backend_radeon,  &backend_rockchip,
diff --git a/external/xe_drm.h b/external/xe_drm.h
new file mode 100644
index 0000000..ba48da5
--- /dev/null
+++ b/external/xe_drm.h
@@ -0,0 +1,1353 @@
+/* SPDX-License-Identifier: MIT */
+/*
+ * Copyright © 2023 Intel Corporation
+ */
+
+#ifndef _XE_DRM_H_
+#define _XE_DRM_H_
+
+#include "drm.h"
+
+#if defined(__cplusplus)
+extern "C" {
+#endif
+
+/*
+ * Please note that modifications to all structs defined here are
+ * subject to backwards-compatibility constraints.
+ * Sections in this file are organized as follows:
+ *   1. IOCTL definition
+ *   2. Extension definition and helper structs
+ *   3. IOCTL's Query structs in the order of the Query's entries.
+ *   4. The rest of IOCTL structs in the order of IOCTL declaration.
+ */
+
+/**
+ * DOC: Xe Device Block Diagram
+ *
+ * The diagram below represents a high-level simplification of a discrete
+ * GPU supported by the Xe driver. It shows some device components which
+ * are necessary to understand this API, as well as how their relations
+ * to each other. This diagram does not represent real hardware::
+ *
+ *   ┌──────────────────────────────────────────────────────────────────┐
+ *   │ ┌──────────────────────────────────────────────────┐ ┌─────────┐ │
+ *   │ │        ┌───────────────────────┐   ┌─────┐       │ │ ┌─────┐ │ │
+ *   │ │        │         VRAM0         ├───┤ ... │       │ │ │VRAM1│ │ │
+ *   │ │        └───────────┬───────────┘   └─GT1─┘       │ │ └──┬──┘ │ │
+ *   │ │ ┌──────────────────┴───────────────────────────┐ │ │ ┌──┴──┐ │ │
+ *   │ │ │ ┌─────────────────────┐  ┌─────────────────┐ │ │ │ │     │ │ │
+ *   │ │ │ │ ┌──┐ ┌──┐ ┌──┐ ┌──┐ │  │ ┌─────┐ ┌─────┐ │ │ │ │ │     │ │ │
+ *   │ │ │ │ │EU│ │EU│ │EU│ │EU│ │  │ │RCS0 │ │BCS0 │ │ │ │ │ │     │ │ │
+ *   │ │ │ │ └──┘ └──┘ └──┘ └──┘ │  │ └─────┘ └─────┘ │ │ │ │ │     │ │ │
+ *   │ │ │ │ ┌──┐ ┌──┐ ┌──┐ ┌──┐ │  │ ┌─────┐ ┌─────┐ │ │ │ │ │     │ │ │
+ *   │ │ │ │ │EU│ │EU│ │EU│ │EU│ │  │ │VCS0 │ │VCS1 │ │ │ │ │ │     │ │ │
+ *   │ │ │ │ └──┘ └──┘ └──┘ └──┘ │  │ └─────┘ └─────┘ │ │ │ │ │     │ │ │
+ *   │ │ │ │ ┌──┐ ┌──┐ ┌──┐ ┌──┐ │  │ ┌─────┐ ┌─────┐ │ │ │ │ │     │ │ │
+ *   │ │ │ │ │EU│ │EU│ │EU│ │EU│ │  │ │VECS0│ │VECS1│ │ │ │ │ │ ... │ │ │
+ *   │ │ │ │ └──┘ └──┘ └──┘ └──┘ │  │ └─────┘ └─────┘ │ │ │ │ │     │ │ │
+ *   │ │ │ │ ┌──┐ ┌──┐ ┌──┐ ┌──┐ │  │ ┌─────┐ ┌─────┐ │ │ │ │ │     │ │ │
+ *   │ │ │ │ │EU│ │EU│ │EU│ │EU│ │  │ │CCS0 │ │CCS1 │ │ │ │ │ │     │ │ │
+ *   │ │ │ │ └──┘ └──┘ └──┘ └──┘ │  │ └─────┘ └─────┘ │ │ │ │ │     │ │ │
+ *   │ │ │ └─────────DSS─────────┘  │ ┌─────┐ ┌─────┐ │ │ │ │ │     │ │ │
+ *   │ │ │                          │ │CCS2 │ │CCS3 │ │ │ │ │ │     │ │ │
+ *   │ │ │ ┌─────┐ ┌─────┐ ┌─────┐  │ └─────┘ └─────┘ │ │ │ │ │     │ │ │
+ *   │ │ │ │ ... │ │ ... │ │ ... │  │                 │ │ │ │ │     │ │ │
+ *   │ │ │ └─DSS─┘ └─DSS─┘ └─DSS─┘  └─────Engines─────┘ │ │ │ │     │ │ │
+ *   │ │ └───────────────────────────GT0────────────────┘ │ │ └─GT2─┘ │ │
+ *   │ └────────────────────────────Tile0─────────────────┘ └─ Tile1──┘ │
+ *   └─────────────────────────────Device0───────┬──────────────────────┘
+ *                                               │
+ *                        ───────────────────────┴────────── PCI bus
+ */
+
+/**
+ * DOC: Xe uAPI Overview
+ *
+ * This section aims to describe the Xe's IOCTL entries, its structs, and other
+ * Xe related uAPI such as uevents and PMU (Platform Monitoring Unit) related
+ * entries and usage.
+ *
+ * List of supported IOCTLs:
+ *  - &DRM_IOCTL_XE_DEVICE_QUERY
+ *  - &DRM_IOCTL_XE_GEM_CREATE
+ *  - &DRM_IOCTL_XE_GEM_MMAP_OFFSET
+ *  - &DRM_IOCTL_XE_VM_CREATE
+ *  - &DRM_IOCTL_XE_VM_DESTROY
+ *  - &DRM_IOCTL_XE_VM_BIND
+ *  - &DRM_IOCTL_XE_EXEC_QUEUE_CREATE
+ *  - &DRM_IOCTL_XE_EXEC_QUEUE_DESTROY
+ *  - &DRM_IOCTL_XE_EXEC_QUEUE_GET_PROPERTY
+ *  - &DRM_IOCTL_XE_EXEC
+ *  - &DRM_IOCTL_XE_WAIT_USER_FENCE
+ */
+
+/*
+ * xe specific ioctls.
+ *
+ * The device specific ioctl range is [DRM_COMMAND_BASE, DRM_COMMAND_END) ie
+ * [0x40, 0xa0) (a0 is excluded). The numbers below are defined as offset
+ * against DRM_COMMAND_BASE and should be between [0x0, 0x60).
+ */
+#define DRM_XE_DEVICE_QUERY		0x00
+#define DRM_XE_GEM_CREATE		0x01
+#define DRM_XE_GEM_MMAP_OFFSET		0x02
+#define DRM_XE_VM_CREATE		0x03
+#define DRM_XE_VM_DESTROY		0x04
+#define DRM_XE_VM_BIND			0x05
+#define DRM_XE_EXEC_QUEUE_CREATE	0x06
+#define DRM_XE_EXEC_QUEUE_DESTROY	0x07
+#define DRM_XE_EXEC_QUEUE_GET_PROPERTY	0x08
+#define DRM_XE_EXEC			0x09
+#define DRM_XE_WAIT_USER_FENCE		0x0a
+/* Must be kept compact -- no holes */
+
+#define DRM_IOCTL_XE_DEVICE_QUERY		DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_DEVICE_QUERY, struct drm_xe_device_query)
+#define DRM_IOCTL_XE_GEM_CREATE			DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_GEM_CREATE, struct drm_xe_gem_create)
+#define DRM_IOCTL_XE_GEM_MMAP_OFFSET		DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_GEM_MMAP_OFFSET, struct drm_xe_gem_mmap_offset)
+#define DRM_IOCTL_XE_VM_CREATE			DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_VM_CREATE, struct drm_xe_vm_create)
+#define DRM_IOCTL_XE_VM_DESTROY			DRM_IOW(DRM_COMMAND_BASE + DRM_XE_VM_DESTROY, struct drm_xe_vm_destroy)
+#define DRM_IOCTL_XE_VM_BIND			DRM_IOW(DRM_COMMAND_BASE + DRM_XE_VM_BIND, struct drm_xe_vm_bind)
+#define DRM_IOCTL_XE_EXEC_QUEUE_CREATE		DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_EXEC_QUEUE_CREATE, struct drm_xe_exec_queue_create)
+#define DRM_IOCTL_XE_EXEC_QUEUE_DESTROY		DRM_IOW(DRM_COMMAND_BASE + DRM_XE_EXEC_QUEUE_DESTROY, struct drm_xe_exec_queue_destroy)
+#define DRM_IOCTL_XE_EXEC_QUEUE_GET_PROPERTY	DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_EXEC_QUEUE_GET_PROPERTY, struct drm_xe_exec_queue_get_property)
+#define DRM_IOCTL_XE_EXEC			DRM_IOW(DRM_COMMAND_BASE + DRM_XE_EXEC, struct drm_xe_exec)
+#define DRM_IOCTL_XE_WAIT_USER_FENCE		DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_WAIT_USER_FENCE, struct drm_xe_wait_user_fence)
+
+/**
+ * DOC: Xe IOCTL Extensions
+ *
+ * Before detailing the IOCTLs and its structs, it is important to highlight
+ * that every IOCTL in Xe is extensible.
+ *
+ * Many interfaces need to grow over time. In most cases we can simply
+ * extend the struct and have userspace pass in more data. Another option,
+ * as demonstrated by Vulkan's approach to providing extensions for forward
+ * and backward compatibility, is to use a list of optional structs to
+ * provide those extra details.
+ *
+ * The key advantage to using an extension chain is that it allows us to
+ * redefine the interface more easily than an ever growing struct of
+ * increasing complexity, and for large parts of that interface to be
+ * entirely optional. The downside is more pointer chasing; chasing across
+ * the boundary with pointers encapsulated inside u64.
+ *
+ * Example chaining:
+ *
+ * .. code-block:: C
+ *
+ *	struct drm_xe_user_extension ext3 {
+ *		.next_extension = 0, // end
+ *		.name = ...,
+ *	};
+ *	struct drm_xe_user_extension ext2 {
+ *		.next_extension = (uintptr_t)&ext3,
+ *		.name = ...,
+ *	};
+ *	struct drm_xe_user_extension ext1 {
+ *		.next_extension = (uintptr_t)&ext2,
+ *		.name = ...,
+ *	};
+ *
+ * Typically the struct drm_xe_user_extension would be embedded in some uAPI
+ * struct, and in this case we would feed it the head of the chain(i.e ext1),
+ * which would then apply all of the above extensions.
+*/
+
+/**
+ * struct drm_xe_user_extension - Base class for defining a chain of extensions
+ */
+struct drm_xe_user_extension {
+	/**
+	 * @next_extension:
+	 *
+	 * Pointer to the next struct drm_xe_user_extension, or zero if the end.
+	 */
+	__u64 next_extension;
+
+	/**
+	 * @name: Name of the extension.
+	 *
+	 * Note that the name here is just some integer.
+	 *
+	 * Also note that the name space for this is not global for the whole
+	 * driver, but rather its scope/meaning is limited to the specific piece
+	 * of uAPI which has embedded the struct drm_xe_user_extension.
+	 */
+	__u32 name;
+
+	/**
+	 * @pad: MBZ
+	 *
+	 * All undefined bits must be zero.
+	 */
+	__u32 pad;
+};
+
+/**
+ * struct drm_xe_ext_set_property - Generic set property extension
+ *
+ * A generic struct that allows any of the Xe's IOCTL to be extended
+ * with a set_property operation.
+ */
+struct drm_xe_ext_set_property {
+	/** @base: base user extension */
+	struct drm_xe_user_extension base;
+
+	/** @property: property to set */
+	__u32 property;
+
+	/** @pad: MBZ */
+	__u32 pad;
+
+	/** @value: property value */
+	__u64 value;
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+/**
+ * struct drm_xe_engine_class_instance - instance of an engine class
+ *
+ * It is returned as part of the @drm_xe_engine, but it also is used as
+ * the input of engine selection for both @drm_xe_exec_queue_create and
+ * @drm_xe_query_engine_cycles
+ *
+ * The @engine_class can be:
+ *  - %DRM_XE_ENGINE_CLASS_RENDER
+ *  - %DRM_XE_ENGINE_CLASS_COPY
+ *  - %DRM_XE_ENGINE_CLASS_VIDEO_DECODE
+ *  - %DRM_XE_ENGINE_CLASS_VIDEO_ENHANCE
+ *  - %DRM_XE_ENGINE_CLASS_COMPUTE
+ *  - %DRM_XE_ENGINE_CLASS_VM_BIND - Kernel only classes (not actual
+ *    hardware engine class). Used for creating ordered queues of VM
+ *    bind operations.
+ */
+struct drm_xe_engine_class_instance {
+#define DRM_XE_ENGINE_CLASS_RENDER		0
+#define DRM_XE_ENGINE_CLASS_COPY		1
+#define DRM_XE_ENGINE_CLASS_VIDEO_DECODE	2
+#define DRM_XE_ENGINE_CLASS_VIDEO_ENHANCE	3
+#define DRM_XE_ENGINE_CLASS_COMPUTE		4
+#define DRM_XE_ENGINE_CLASS_VM_BIND		5
+	/** @engine_class: engine class id */
+	__u16 engine_class;
+	/** @engine_instance: engine instance id */
+	__u16 engine_instance;
+	/** @gt_id: Unique ID of this GT within the PCI Device */
+	__u16 gt_id;
+	/** @pad: MBZ */
+	__u16 pad;
+};
+
+/**
+ * struct drm_xe_engine - describe hardware engine
+ */
+struct drm_xe_engine {
+	/** @instance: The @drm_xe_engine_class_instance */
+	struct drm_xe_engine_class_instance instance;
+
+	/** @reserved: Reserved */
+	__u64 reserved[3];
+};
+
+/**
+ * struct drm_xe_query_engines - describe engines
+ *
+ * If a query is made with a struct @drm_xe_device_query where .query
+ * is equal to %DRM_XE_DEVICE_QUERY_ENGINES, then the reply uses an array of
+ * struct @drm_xe_query_engines in .data.
+ */
+struct drm_xe_query_engines {
+	/** @num_engines: number of engines returned in @engines */
+	__u32 num_engines;
+	/** @pad: MBZ */
+	__u32 pad;
+	/** @engines: The returned engines for this device */
+	struct drm_xe_engine engines[];
+};
+
+/**
+ * enum drm_xe_memory_class - Supported memory classes.
+ */
+enum drm_xe_memory_class {
+	/** @DRM_XE_MEM_REGION_CLASS_SYSMEM: Represents system memory. */
+	DRM_XE_MEM_REGION_CLASS_SYSMEM = 0,
+	/**
+	 * @DRM_XE_MEM_REGION_CLASS_VRAM: On discrete platforms, this
+	 * represents the memory that is local to the device, which we
+	 * call VRAM. Not valid on integrated platforms.
+	 */
+	DRM_XE_MEM_REGION_CLASS_VRAM
+};
+
+/**
+ * struct drm_xe_mem_region - Describes some region as known to
+ * the driver.
+ */
+struct drm_xe_mem_region {
+	/**
+	 * @mem_class: The memory class describing this region.
+	 *
+	 * See enum drm_xe_memory_class for supported values.
+	 */
+	__u16 mem_class;
+	/**
+	 * @instance: The unique ID for this region, which serves as the
+	 * index in the placement bitmask used as argument for
+	 * &DRM_IOCTL_XE_GEM_CREATE
+	 */
+	__u16 instance;
+	/**
+	 * @min_page_size: Min page-size in bytes for this region.
+	 *
+	 * When the kernel allocates memory for this region, the
+	 * underlying pages will be at least @min_page_size in size.
+	 * Buffer objects with an allowable placement in this region must be
+	 * created with a size aligned to this value.
+	 * GPU virtual address mappings of (parts of) buffer objects that
+	 * may be placed in this region must also have their GPU virtual
+	 * address and range aligned to this value.
+	 * Affected IOCTLS will return %-EINVAL if alignment restrictions are
+	 * not met.
+	 */
+	__u32 min_page_size;
+	/**
+	 * @total_size: The usable size in bytes for this region.
+	 */
+	__u64 total_size;
+	/**
+	 * @used: Estimate of the memory used in bytes for this region.
+	 *
+	 * Requires CAP_PERFMON or CAP_SYS_ADMIN to get reliable
+	 * accounting.  Without this the value here will always equal
+	 * zero.
+	 */
+	__u64 used;
+	/**
+	 * @cpu_visible_size: How much of this region can be CPU
+	 * accessed, in bytes.
+	 *
+	 * This will always be <= @total_size, and the remainder (if
+	 * any) will not be CPU accessible. If the CPU accessible part
+	 * is smaller than @total_size then this is referred to as a
+	 * small BAR system.
+	 *
+	 * On systems without small BAR (full BAR), the probed_size will
+	 * always equal the @total_size, since all of it will be CPU
+	 * accessible.
+	 *
+	 * Note this is only tracked for DRM_XE_MEM_REGION_CLASS_VRAM
+	 * regions (for other types the value here will always equal
+	 * zero).
+	 */
+	__u64 cpu_visible_size;
+	/**
+	 * @cpu_visible_used: Estimate of CPU visible memory used, in
+	 * bytes.
+	 *
+	 * Requires CAP_PERFMON or CAP_SYS_ADMIN to get reliable
+	 * accounting. Without this the value here will always equal
+	 * zero.  Note this is only currently tracked for
+	 * DRM_XE_MEM_REGION_CLASS_VRAM regions (for other types the value
+	 * here will always be zero).
+	 */
+	__u64 cpu_visible_used;
+	/** @reserved: Reserved */
+	__u64 reserved[6];
+};
+
+/**
+ * struct drm_xe_query_mem_regions - describe memory regions
+ *
+ * If a query is made with a struct drm_xe_device_query where .query
+ * is equal to DRM_XE_DEVICE_QUERY_MEM_REGIONS, then the reply uses
+ * struct drm_xe_query_mem_regions in .data.
+ */
+struct drm_xe_query_mem_regions {
+	/** @num_mem_regions: number of memory regions returned in @mem_regions */
+	__u32 num_mem_regions;
+	/** @pad: MBZ */
+	__u32 pad;
+	/** @mem_regions: The returned memory regions for this device */
+	struct drm_xe_mem_region mem_regions[];
+};
+
+/**
+ * struct drm_xe_query_config - describe the device configuration
+ *
+ * If a query is made with a struct drm_xe_device_query where .query
+ * is equal to DRM_XE_DEVICE_QUERY_CONFIG, then the reply uses
+ * struct drm_xe_query_config in .data.
+ *
+ * The index in @info can be:
+ *  - %DRM_XE_QUERY_CONFIG_REV_AND_DEVICE_ID - Device ID (lower 16 bits)
+ *    and the device revision (next 8 bits)
+ *  - %DRM_XE_QUERY_CONFIG_FLAGS - Flags describing the device
+ *    configuration, see list below
+ *
+ *    - %DRM_XE_QUERY_CONFIG_FLAG_HAS_VRAM - Flag is set if the device
+ *      has usable VRAM
+ *  - %DRM_XE_QUERY_CONFIG_MIN_ALIGNMENT - Minimal memory alignment
+ *    required by this device, typically SZ_4K or SZ_64K
+ *  - %DRM_XE_QUERY_CONFIG_VA_BITS - Maximum bits of a virtual address
+ *  - %DRM_XE_QUERY_CONFIG_MAX_EXEC_QUEUE_PRIORITY - Value of the highest
+ *    available exec queue priority
+ */
+struct drm_xe_query_config {
+	/** @num_params: number of parameters returned in info */
+	__u32 num_params;
+
+	/** @pad: MBZ */
+	__u32 pad;
+
+#define DRM_XE_QUERY_CONFIG_REV_AND_DEVICE_ID	0
+#define DRM_XE_QUERY_CONFIG_FLAGS			1
+	#define DRM_XE_QUERY_CONFIG_FLAG_HAS_VRAM	(1 << 0)
+#define DRM_XE_QUERY_CONFIG_MIN_ALIGNMENT		2
+#define DRM_XE_QUERY_CONFIG_VA_BITS			3
+#define DRM_XE_QUERY_CONFIG_MAX_EXEC_QUEUE_PRIORITY	4
+	/** @info: array of elements containing the config info */
+	__u64 info[];
+};
+
+/**
+ * struct drm_xe_gt - describe an individual GT.
+ *
+ * To be used with drm_xe_query_gt_list, which will return a list with all the
+ * existing GT individual descriptions.
+ * Graphics Technology (GT) is a subset of a GPU/tile that is responsible for
+ * implementing graphics and/or media operations.
+ *
+ * The index in @type can be:
+ *  - %DRM_XE_QUERY_GT_TYPE_MAIN
+ *  - %DRM_XE_QUERY_GT_TYPE_MEDIA
+ */
+struct drm_xe_gt {
+#define DRM_XE_QUERY_GT_TYPE_MAIN		0
+#define DRM_XE_QUERY_GT_TYPE_MEDIA		1
+	/** @type: GT type: Main or Media */
+	__u16 type;
+	/** @tile_id: Tile ID where this GT lives (Information only) */
+	__u16 tile_id;
+	/** @gt_id: Unique ID of this GT within the PCI Device */
+	__u16 gt_id;
+	/** @pad: MBZ */
+	__u16 pad[3];
+	/** @reference_clock: A clock frequency for timestamp */
+	__u32 reference_clock;
+	/**
+	 * @near_mem_regions: Bit mask of instances from
+	 * drm_xe_query_mem_regions that are nearest to the current engines
+	 * of this GT.
+	 * Each index in this mask refers directly to the struct
+	 * drm_xe_query_mem_regions' instance, no assumptions should
+	 * be made about order. The type of each region is described
+	 * by struct drm_xe_query_mem_regions' mem_class.
+	 */
+	__u64 near_mem_regions;
+	/**
+	 * @far_mem_regions: Bit mask of instances from
+	 * drm_xe_query_mem_regions that are far from the engines of this GT.
+	 * In general, they have extra indirections when compared to the
+	 * @near_mem_regions. For a discrete device this could mean system
+	 * memory and memory living in a different tile.
+	 * Each index in this mask refers directly to the struct
+	 * drm_xe_query_mem_regions' instance, no assumptions should
+	 * be made about order. The type of each region is described
+	 * by struct drm_xe_query_mem_regions' mem_class.
+	 */
+	__u64 far_mem_regions;
+	/** @reserved: Reserved */
+	__u64 reserved[8];
+};
+
+/**
+ * struct drm_xe_query_gt_list - A list with GT description items.
+ *
+ * If a query is made with a struct drm_xe_device_query where .query
+ * is equal to DRM_XE_DEVICE_QUERY_GT_LIST, then the reply uses struct
+ * drm_xe_query_gt_list in .data.
+ */
+struct drm_xe_query_gt_list {
+	/** @num_gt: number of GT items returned in gt_list */
+	__u32 num_gt;
+	/** @pad: MBZ */
+	__u32 pad;
+	/** @gt_list: The GT list returned for this device */
+	struct drm_xe_gt gt_list[];
+};
+
+/**
+ * struct drm_xe_query_topology_mask - describe the topology mask of a GT
+ *
+ * This is the hardware topology which reflects the internal physical
+ * structure of the GPU.
+ *
+ * If a query is made with a struct drm_xe_device_query where .query
+ * is equal to DRM_XE_DEVICE_QUERY_GT_TOPOLOGY, then the reply uses
+ * struct drm_xe_query_topology_mask in .data.
+ *
+ * The @type can be:
+ *  - %DRM_XE_TOPO_DSS_GEOMETRY - To query the mask of Dual Sub Slices
+ *    (DSS) available for geometry operations. For example a query response
+ *    containing the following in mask:
+ *    ``DSS_GEOMETRY    ff ff ff ff 00 00 00 00``
+ *    means 32 DSS are available for geometry.
+ *  - %DRM_XE_TOPO_DSS_COMPUTE - To query the mask of Dual Sub Slices
+ *    (DSS) available for compute operations. For example a query response
+ *    containing the following in mask:
+ *    ``DSS_COMPUTE    ff ff ff ff 00 00 00 00``
+ *    means 32 DSS are available for compute.
+ *  - %DRM_XE_TOPO_EU_PER_DSS - To query the mask of Execution Units (EU)
+ *    available per Dual Sub Slices (DSS). For example a query response
+ *    containing the following in mask:
+ *    ``EU_PER_DSS    ff ff 00 00 00 00 00 00``
+ *    means each DSS has 16 EU.
+ */
+struct drm_xe_query_topology_mask {
+	/** @gt_id: GT ID the mask is associated with */
+	__u16 gt_id;
+
+#define DRM_XE_TOPO_DSS_GEOMETRY	(1 << 0)
+#define DRM_XE_TOPO_DSS_COMPUTE		(1 << 1)
+#define DRM_XE_TOPO_EU_PER_DSS		(1 << 2)
+	/** @type: type of mask */
+	__u16 type;
+
+	/** @num_bytes: number of bytes in requested mask */
+	__u32 num_bytes;
+
+	/** @mask: little-endian mask of @num_bytes */
+	__u8 mask[];
+};
+
+/**
+ * struct drm_xe_query_engine_cycles - correlate CPU and GPU timestamps
+ *
+ * If a query is made with a struct drm_xe_device_query where .query is equal to
+ * DRM_XE_DEVICE_QUERY_ENGINE_CYCLES, then the reply uses struct drm_xe_query_engine_cycles
+ * in .data. struct drm_xe_query_engine_cycles is allocated by the user and
+ * .data points to this allocated structure.
+ *
+ * The query returns the engine cycles, which along with GT's @reference_clock,
+ * can be used to calculate the engine timestamp. In addition the
+ * query returns a set of cpu timestamps that indicate when the command
+ * streamer cycle count was captured.
+ */
+struct drm_xe_query_engine_cycles {
+	/**
+	 * @eci: This is input by the user and is the engine for which command
+	 * streamer cycles is queried.
+	 */
+	struct drm_xe_engine_class_instance eci;
+
+	/**
+	 * @clockid: This is input by the user and is the reference clock id for
+	 * CPU timestamp. For definition, see clock_gettime(2) and
+	 * perf_event_open(2). Supported clock ids are CLOCK_MONOTONIC,
+	 * CLOCK_MONOTONIC_RAW, CLOCK_REALTIME, CLOCK_BOOTTIME, CLOCK_TAI.
+	 */
+	__s32 clockid;
+
+	/** @width: Width of the engine cycle counter in bits. */
+	__u32 width;
+
+	/**
+	 * @engine_cycles: Engine cycles as read from its register
+	 * at 0x358 offset.
+	 */
+	__u64 engine_cycles;
+
+	/**
+	 * @cpu_timestamp: CPU timestamp in ns. The timestamp is captured before
+	 * reading the engine_cycles register using the reference clockid set by the
+	 * user.
+	 */
+	__u64 cpu_timestamp;
+
+	/**
+	 * @cpu_delta: Time delta in ns captured around reading the lower dword
+	 * of the engine_cycles register.
+	 */
+	__u64 cpu_delta;
+};
+
+/**
+ * struct drm_xe_device_query - Input of &DRM_IOCTL_XE_DEVICE_QUERY - main
+ * structure to query device information
+ *
+ * The user selects the type of data to query among DRM_XE_DEVICE_QUERY_*
+ * and sets the value in the query member. This determines the type of
+ * the structure provided by the driver in data, among struct drm_xe_query_*.
+ *
+ * The @query can be:
+ *  - %DRM_XE_DEVICE_QUERY_ENGINES
+ *  - %DRM_XE_DEVICE_QUERY_MEM_REGIONS
+ *  - %DRM_XE_DEVICE_QUERY_CONFIG
+ *  - %DRM_XE_DEVICE_QUERY_GT_LIST
+ *  - %DRM_XE_DEVICE_QUERY_HWCONFIG - Query type to retrieve the hardware
+ *    configuration of the device such as information on slices, memory,
+ *    caches, and so on. It is provided as a table of key / value
+ *    attributes.
+ *  - %DRM_XE_DEVICE_QUERY_GT_TOPOLOGY
+ *  - %DRM_XE_DEVICE_QUERY_ENGINE_CYCLES
+ *
+ * If size is set to 0, the driver fills it with the required size for
+ * the requested type of data to query. If size is equal to the required
+ * size, the queried information is copied into data. If size is set to
+ * a value different from 0 and different from the required size, the
+ * IOCTL call returns -EINVAL.
+ *
+ * For example the following code snippet allows retrieving and printing
+ * information about the device engines with DRM_XE_DEVICE_QUERY_ENGINES:
+ *
+ * .. code-block:: C
+ *
+ *     struct drm_xe_query_engines *engines;
+ *     struct drm_xe_device_query query = {
+ *         .extensions = 0,
+ *         .query = DRM_XE_DEVICE_QUERY_ENGINES,
+ *         .size = 0,
+ *         .data = 0,
+ *     };
+ *     ioctl(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query);
+ *     engines = malloc(query.size);
+ *     query.data = (uintptr_t)engines;
+ *     ioctl(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query);
+ *     for (int i = 0; i < engines->num_engines; i++) {
+ *         printf("Engine %d: %s\n", i,
+ *             engines->engines[i].instance.engine_class ==
+ *                 DRM_XE_ENGINE_CLASS_RENDER ? "RENDER":
+ *             engines->engines[i].instance.engine_class ==
+ *                 DRM_XE_ENGINE_CLASS_COPY ? "COPY":
+ *             engines->engines[i].instance.engine_class ==
+ *                 DRM_XE_ENGINE_CLASS_VIDEO_DECODE ? "VIDEO_DECODE":
+ *             engines->engines[i].instance.engine_class ==
+ *                 DRM_XE_ENGINE_CLASS_VIDEO_ENHANCE ? "VIDEO_ENHANCE":
+ *             engines->engines[i].instance.engine_class ==
+ *                 DRM_XE_ENGINE_CLASS_COMPUTE ? "COMPUTE":
+ *             "UNKNOWN");
+ *     }
+ *     free(engines);
+ */
+struct drm_xe_device_query {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+#define DRM_XE_DEVICE_QUERY_ENGINES		0
+#define DRM_XE_DEVICE_QUERY_MEM_REGIONS		1
+#define DRM_XE_DEVICE_QUERY_CONFIG		2
+#define DRM_XE_DEVICE_QUERY_GT_LIST		3
+#define DRM_XE_DEVICE_QUERY_HWCONFIG		4
+#define DRM_XE_DEVICE_QUERY_GT_TOPOLOGY		5
+#define DRM_XE_DEVICE_QUERY_ENGINE_CYCLES	6
+	/** @query: The type of data to query */
+	__u32 query;
+
+	/** @size: Size of the queried data */
+	__u32 size;
+
+	/** @data: Queried data is placed here */
+	__u64 data;
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+/**
+ * struct drm_xe_gem_create - Input of &DRM_IOCTL_XE_GEM_CREATE - A structure for
+ * gem creation
+ *
+ * The @flags can be:
+ *  - %DRM_XE_GEM_CREATE_FLAG_DEFER_BACKING
+ *  - %DRM_XE_GEM_CREATE_FLAG_SCANOUT
+ *  - %DRM_XE_GEM_CREATE_FLAG_NEEDS_VISIBLE_VRAM - When using VRAM as a
+ *    possible placement, ensure that the corresponding VRAM allocation
+ *    will always use the CPU accessible part of VRAM. This is important
+ *    for small-bar systems (on full-bar systems this gets turned into a
+ *    noop).
+ *    Note1: System memory can be used as an extra placement if the kernel
+ *    should spill the allocation to system memory, if space can't be made
+ *    available in the CPU accessible part of VRAM (giving the same
+ *    behaviour as the i915 interface, see
+ *    I915_GEM_CREATE_EXT_FLAG_NEEDS_CPU_ACCESS).
+ *    Note2: For clear-color CCS surfaces the kernel needs to read the
+ *    clear-color value stored in the buffer, and on discrete platforms we
+ *    need to use VRAM for display surfaces, therefore the kernel requires
+ *    setting this flag for such objects, otherwise an error is thrown on
+ *    small-bar systems.
+ *
+ * @cpu_caching supports the following values:
+ *  - %DRM_XE_GEM_CPU_CACHING_WB - Allocate the pages with write-back
+ *    caching. On iGPU this can't be used for scanout surfaces. Currently
+ *    not allowed for objects placed in VRAM.
+ *  - %DRM_XE_GEM_CPU_CACHING_WC - Allocate the pages as write-combined. This
+ *    is uncached. Scanout surfaces should likely use this. All objects
+ *    that can be placed in VRAM must use this.
+ */
+struct drm_xe_gem_create {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+	/**
+	 * @size: Size of the object to be created, must match region
+	 * (system or vram) minimum alignment (&min_page_size).
+	 */
+	__u64 size;
+
+	/**
+	 * @placement: A mask of memory instances of where BO can be placed.
+	 * Each index in this mask refers directly to the struct
+	 * drm_xe_query_mem_regions' instance, no assumptions should
+	 * be made about order. The type of each region is described
+	 * by struct drm_xe_query_mem_regions' mem_class.
+	 */
+	__u32 placement;
+
+#define DRM_XE_GEM_CREATE_FLAG_DEFER_BACKING		(1 << 0)
+#define DRM_XE_GEM_CREATE_FLAG_SCANOUT			(1 << 1)
+#define DRM_XE_GEM_CREATE_FLAG_NEEDS_VISIBLE_VRAM	(1 << 2)
+	/**
+	 * @flags: Flags, currently a mask of memory instances of where BO can
+	 * be placed
+	 */
+	__u32 flags;
+
+	/**
+	 * @vm_id: Attached VM, if any
+	 *
+	 * If a VM is specified, this BO must:
+	 *
+	 *  1. Only ever be bound to that VM.
+	 *  2. Cannot be exported as a PRIME fd.
+	 */
+	__u32 vm_id;
+
+	/**
+	 * @handle: Returned handle for the object.
+	 *
+	 * Object handles are nonzero.
+	 */
+	__u32 handle;
+
+#define DRM_XE_GEM_CPU_CACHING_WB                      1
+#define DRM_XE_GEM_CPU_CACHING_WC                      2
+	/**
+	 * @cpu_caching: The CPU caching mode to select for this object. If
+	 * mmaping the object the mode selected here will also be used.
+	 */
+	__u16 cpu_caching;
+	/** @pad: MBZ */
+	__u16 pad[3];
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+/**
+ * struct drm_xe_gem_mmap_offset - Input of &DRM_IOCTL_XE_GEM_MMAP_OFFSET
+ */
+struct drm_xe_gem_mmap_offset {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+	/** @handle: Handle for the object being mapped. */
+	__u32 handle;
+
+	/** @flags: Must be zero */
+	__u32 flags;
+
+	/** @offset: The fake offset to use for subsequent mmap call */
+	__u64 offset;
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+/**
+ * struct drm_xe_vm_create - Input of &DRM_IOCTL_XE_VM_CREATE
+ *
+ * The @flags can be:
+ *  - %DRM_XE_VM_CREATE_FLAG_SCRATCH_PAGE
+ *  - %DRM_XE_VM_CREATE_FLAG_LR_MODE - An LR, or Long Running VM accepts
+ *    exec submissions to its exec_queues that don't have an upper time
+ *    limit on the job execution time. But exec submissions to these
+ *    don't allow any of the flags DRM_XE_SYNC_FLAG_SYNCOBJ,
+ *    DRM_XE_SYNC_FLAG_TIMELINE_SYNCOBJ, DRM_XE_SYNC_FLAG_DMA_BUF,
+ *    used as out-syncobjs, that is, together with DRM_XE_SYNC_FLAG_SIGNAL.
+ *    LR VMs can be created in recoverable page-fault mode using
+ *    DRM_XE_VM_CREATE_FLAG_FAULT_MODE, if the device supports it.
+ *    If that flag is omitted, the UMD can not rely on the slightly
+ *    different per-VM overcommit semantics that are enabled by
+ *    DRM_XE_VM_CREATE_FLAG_FAULT_MODE (see below), but KMD may
+ *    still enable recoverable pagefaults if supported by the device.
+ *  - %DRM_XE_VM_CREATE_FLAG_FAULT_MODE - Requires also
+ *    DRM_XE_VM_CREATE_FLAG_LR_MODE. It allows memory to be allocated on
+ *    demand when accessed, and also allows per-VM overcommit of memory.
+ *    The xe driver internally uses recoverable pagefaults to implement
+ *    this.
+ */
+struct drm_xe_vm_create {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+#define DRM_XE_VM_CREATE_FLAG_SCRATCH_PAGE	(1 << 0)
+#define DRM_XE_VM_CREATE_FLAG_LR_MODE	        (1 << 1)
+#define DRM_XE_VM_CREATE_FLAG_FAULT_MODE	(1 << 2)
+	/** @flags: Flags */
+	__u32 flags;
+
+	/** @vm_id: Returned VM ID */
+	__u32 vm_id;
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+/**
+ * struct drm_xe_vm_destroy - Input of &DRM_IOCTL_XE_VM_DESTROY
+ */
+struct drm_xe_vm_destroy {
+	/** @vm_id: VM ID */
+	__u32 vm_id;
+
+	/** @pad: MBZ */
+	__u32 pad;
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+/**
+ * struct drm_xe_vm_bind_op - run bind operations
+ *
+ * The @op can be:
+ *  - %DRM_XE_VM_BIND_OP_MAP
+ *  - %DRM_XE_VM_BIND_OP_UNMAP
+ *  - %DRM_XE_VM_BIND_OP_MAP_USERPTR
+ *  - %DRM_XE_VM_BIND_OP_UNMAP_ALL
+ *  - %DRM_XE_VM_BIND_OP_PREFETCH
+ *
+ * and the @flags can be:
+ *  - %DRM_XE_VM_BIND_FLAG_READONLY
+ *  - %DRM_XE_VM_BIND_FLAG_ASYNC
+ *  - %DRM_XE_VM_BIND_FLAG_IMMEDIATE - Valid on a faulting VM only, do the
+ *    MAP operation immediately rather than deferring the MAP to the page
+ *    fault handler.
+ *  - %DRM_XE_VM_BIND_FLAG_NULL - When the NULL flag is set, the page
+ *    tables are setup with a special bit which indicates writes are
+ *    dropped and all reads return zero. In the future, the NULL flags
+ *    will only be valid for DRM_XE_VM_BIND_OP_MAP operations, the BO
+ *    handle MBZ, and the BO offset MBZ. This flag is intended to
+ *    implement VK sparse bindings.
+ */
+struct drm_xe_vm_bind_op {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+	/**
+	 * @obj: GEM object to operate on, MBZ for MAP_USERPTR, MBZ for UNMAP
+	 */
+	__u32 obj;
+
+	/**
+	 * @pat_index: The platform defined @pat_index to use for this mapping.
+	 * The index basically maps to some predefined memory attributes,
+	 * including things like caching, coherency, compression etc.  The exact
+	 * meaning of the pat_index is platform specific and defined in the
+	 * Bspec and PRMs.  When the KMD sets up the binding the index here is
+	 * encoded into the ppGTT PTE.
+	 *
+	 * For coherency the @pat_index needs to be at least 1way coherent when
+	 * drm_xe_gem_create.cpu_caching is DRM_XE_GEM_CPU_CACHING_WB. The KMD
+	 * will extract the coherency mode from the @pat_index and reject if
+	 * there is a mismatch (see note below for pre-MTL platforms).
+	 *
+	 * Note: On pre-MTL platforms there is only a caching mode and no
+	 * explicit coherency mode, but on such hardware there is always a
+	 * shared-LLC (or is dgpu) so all GT memory accesses are coherent with
+	 * CPU caches even with the caching mode set as uncached.  It's only the
+	 * display engine that is incoherent (on dgpu it must be in VRAM which
+	 * is always mapped as WC on the CPU). However to keep the uapi somewhat
+	 * consistent with newer platforms the KMD groups the different cache
+	 * levels into the following coherency buckets on all pre-MTL platforms:
+	 *
+	 *	ppGTT UC -> COH_NONE
+	 *	ppGTT WC -> COH_NONE
+	 *	ppGTT WT -> COH_NONE
+	 *	ppGTT WB -> COH_AT_LEAST_1WAY
+	 *
+	 * In practice UC/WC/WT should only ever used for scanout surfaces on
+	 * such platforms (or perhaps in general for dma-buf if shared with
+	 * another device) since it is only the display engine that is actually
+	 * incoherent.  Everything else should typically use WB given that we
+	 * have a shared-LLC.  On MTL+ this completely changes and the HW
+	 * defines the coherency mode as part of the @pat_index, where
+	 * incoherent GT access is possible.
+	 *
+	 * Note: For userptr and externally imported dma-buf the kernel expects
+	 * either 1WAY or 2WAY for the @pat_index.
+	 *
+	 * For DRM_XE_VM_BIND_FLAG_NULL bindings there are no KMD restrictions
+	 * on the @pat_index. For such mappings there is no actual memory being
+	 * mapped (the address in the PTE is invalid), so the various PAT memory
+	 * attributes likely do not apply.  Simply leaving as zero is one
+	 * option (still a valid pat_index).
+	 */
+	__u16 pat_index;
+
+	/** @pad: MBZ */
+	__u16 pad;
+
+	union {
+		/**
+		 * @obj_offset: Offset into the object, MBZ for CLEAR_RANGE,
+		 * ignored for unbind
+		 */
+		__u64 obj_offset;
+
+		/** @userptr: user pointer to bind on */
+		__u64 userptr;
+	};
+
+	/**
+	 * @range: Number of bytes from the object to bind to addr, MBZ for UNMAP_ALL
+	 */
+	__u64 range;
+
+	/** @addr: Address to operate on, MBZ for UNMAP_ALL */
+	__u64 addr;
+
+#define DRM_XE_VM_BIND_OP_MAP		0x0
+#define DRM_XE_VM_BIND_OP_UNMAP		0x1
+#define DRM_XE_VM_BIND_OP_MAP_USERPTR	0x2
+#define DRM_XE_VM_BIND_OP_UNMAP_ALL	0x3
+#define DRM_XE_VM_BIND_OP_PREFETCH	0x4
+	/** @op: Bind operation to perform */
+	__u32 op;
+
+#define DRM_XE_VM_BIND_FLAG_READONLY	(1 << 0)
+#define DRM_XE_VM_BIND_FLAG_IMMEDIATE	(1 << 1)
+#define DRM_XE_VM_BIND_FLAG_NULL	(1 << 2)
+	/** @flags: Bind flags */
+	__u32 flags;
+
+	/**
+	 * @prefetch_mem_region_instance: Memory region to prefetch VMA to.
+	 * It is a region instance, not a mask.
+	 * To be used only with %DRM_XE_VM_BIND_OP_PREFETCH operation.
+	 */
+	__u32 prefetch_mem_region_instance;
+
+	/** @pad2: MBZ */
+	__u32 pad2;
+
+	/** @reserved: Reserved */
+	__u64 reserved[3];
+};
+
+/**
+ * struct drm_xe_vm_bind - Input of &DRM_IOCTL_XE_VM_BIND
+ *
+ * Below is an example of a minimal use of @drm_xe_vm_bind to
+ * asynchronously bind the buffer `data` at address `BIND_ADDRESS` to
+ * illustrate `userptr`. It can be synchronized by using the example
+ * provided for @drm_xe_sync.
+ *
+ * .. code-block:: C
+ *
+ *     data = aligned_alloc(ALIGNMENT, BO_SIZE);
+ *     struct drm_xe_vm_bind bind = {
+ *         .vm_id = vm,
+ *         .num_binds = 1,
+ *         .bind.obj = 0,
+ *         .bind.obj_offset = to_user_pointer(data),
+ *         .bind.range = BO_SIZE,
+ *         .bind.addr = BIND_ADDRESS,
+ *         .bind.op = DRM_XE_VM_BIND_OP_MAP_USERPTR,
+ *         .bind.flags = 0,
+ *         .num_syncs = 1,
+ *         .syncs = &sync,
+ *         .exec_queue_id = 0,
+ *     };
+ *     ioctl(fd, DRM_IOCTL_XE_VM_BIND, &bind);
+ *
+ */
+struct drm_xe_vm_bind {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+	/** @vm_id: The ID of the VM to bind to */
+	__u32 vm_id;
+
+	/**
+	 * @exec_queue_id: exec_queue_id, must be of class DRM_XE_ENGINE_CLASS_VM_BIND
+	 * and exec queue must have same vm_id. If zero, the default VM bind engine
+	 * is used.
+	 */
+	__u32 exec_queue_id;
+
+	/** @pad: MBZ */
+	__u32 pad;
+
+	/** @num_binds: number of binds in this IOCTL */
+	__u32 num_binds;
+
+	union {
+		/** @bind: used if num_binds == 1 */
+		struct drm_xe_vm_bind_op bind;
+
+		/**
+		 * @vector_of_binds: userptr to array of struct
+		 * drm_xe_vm_bind_op if num_binds > 1
+		 */
+		__u64 vector_of_binds;
+	};
+
+	/** @pad2: MBZ */
+	__u32 pad2;
+
+	/** @num_syncs: amount of syncs to wait on */
+	__u32 num_syncs;
+
+	/** @syncs: pointer to struct drm_xe_sync array */
+	__u64 syncs;
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+/**
+ * struct drm_xe_exec_queue_create - Input of &DRM_IOCTL_XE_EXEC_QUEUE_CREATE
+ *
+ * The example below shows how to use @drm_xe_exec_queue_create to create
+ * a simple exec_queue (no parallel submission) of class
+ * &DRM_XE_ENGINE_CLASS_RENDER.
+ *
+ * .. code-block:: C
+ *
+ *     struct drm_xe_engine_class_instance instance = {
+ *         .engine_class = DRM_XE_ENGINE_CLASS_RENDER,
+ *     };
+ *     struct drm_xe_exec_queue_create exec_queue_create = {
+ *          .extensions = 0,
+ *          .vm_id = vm,
+ *          .num_bb_per_exec = 1,
+ *          .num_eng_per_bb = 1,
+ *          .instances = to_user_pointer(&instance),
+ *     };
+ *     ioctl(fd, DRM_IOCTL_XE_EXEC_QUEUE_CREATE, &exec_queue_create);
+ *
+ */
+struct drm_xe_exec_queue_create {
+#define DRM_XE_EXEC_QUEUE_EXTENSION_SET_PROPERTY		0
+#define   DRM_XE_EXEC_QUEUE_SET_PROPERTY_PRIORITY		0
+#define   DRM_XE_EXEC_QUEUE_SET_PROPERTY_TIMESLICE		1
+#define   DRM_XE_EXEC_QUEUE_SET_PROPERTY_PREEMPTION_TIMEOUT	2
+#define   DRM_XE_EXEC_QUEUE_SET_PROPERTY_PERSISTENCE		3
+#define   DRM_XE_EXEC_QUEUE_SET_PROPERTY_JOB_TIMEOUT		4
+#define   DRM_XE_EXEC_QUEUE_SET_PROPERTY_ACC_TRIGGER		5
+#define   DRM_XE_EXEC_QUEUE_SET_PROPERTY_ACC_NOTIFY		6
+#define   DRM_XE_EXEC_QUEUE_SET_PROPERTY_ACC_GRANULARITY	7
+/* Monitor 128KB contiguous region with 4K sub-granularity */
+#define     DRM_XE_ACC_GRANULARITY_128K				0
+/* Monitor 2MB contiguous region with 64KB sub-granularity */
+#define     DRM_XE_ACC_GRANULARITY_2M				1
+/* Monitor 16MB contiguous region with 512KB sub-granularity */
+#define     DRM_XE_ACC_GRANULARITY_16M				2
+/* Monitor 64MB contiguous region with 2M sub-granularity */
+#define     DRM_XE_ACC_GRANULARITY_64M				3
+
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+	/** @width: submission width (number BB per exec) for this exec queue */
+	__u16 width;
+
+	/** @num_placements: number of valid placements for this exec queue */
+	__u16 num_placements;
+
+	/** @vm_id: VM to use for this exec queue */
+	__u32 vm_id;
+
+	/** @flags: MBZ */
+	__u32 flags;
+
+	/** @exec_queue_id: Returned exec queue ID */
+	__u32 exec_queue_id;
+
+	/**
+	 * @instances: user pointer to a 2-d array of struct
+	 * drm_xe_engine_class_instance
+	 *
+	 * length = width (i) * num_placements (j)
+	 * index = j + i * width
+	 */
+	__u64 instances;
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+/**
+ * struct drm_xe_exec_queue_destroy - Input of &DRM_IOCTL_XE_EXEC_QUEUE_DESTROY
+ */
+struct drm_xe_exec_queue_destroy {
+	/** @exec_queue_id: Exec queue ID */
+	__u32 exec_queue_id;
+
+	/** @pad: MBZ */
+	__u32 pad;
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+/**
+ * struct drm_xe_exec_queue_get_property - Input of &DRM_IOCTL_XE_EXEC_QUEUE_GET_PROPERTY
+ *
+ * The @property can be:
+ *  - %DRM_XE_EXEC_QUEUE_GET_PROPERTY_BAN
+ */
+struct drm_xe_exec_queue_get_property {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+	/** @exec_queue_id: Exec queue ID */
+	__u32 exec_queue_id;
+
+#define DRM_XE_EXEC_QUEUE_GET_PROPERTY_BAN	0
+	/** @property: property to get */
+	__u32 property;
+
+	/** @value: property value */
+	__u64 value;
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+/**
+ * struct drm_xe_sync - sync object
+ *
+ * The @type can be:
+ *  - %DRM_XE_SYNC_TYPE_SYNCOBJ
+ *  - %DRM_XE_SYNC_TYPE_TIMELINE_SYNCOBJ
+ *  - %DRM_XE_SYNC_TYPE_USER_FENCE
+ *
+ * and the @flags can be:
+ *  - %DRM_XE_SYNC_FLAG_SIGNAL
+ *
+ * A minimal use of @drm_xe_sync looks like this:
+ *
+ * .. code-block:: C
+ *
+ *     struct drm_xe_sync sync = {
+ *         .flags = DRM_XE_SYNC_FLAG_SIGNAL,
+ *         .type = DRM_XE_SYNC_TYPE_SYNCOBJ,
+ *     };
+ *     struct drm_syncobj_create syncobj_create = { 0 };
+ *     ioctl(fd, DRM_IOCTL_SYNCOBJ_CREATE, &syncobj_create);
+ *     sync.handle = syncobj_create.handle;
+ *         ...
+ *         use of &sync in drm_xe_exec or drm_xe_vm_bind
+ *         ...
+ *     struct drm_syncobj_wait wait = {
+ *         .handles = &sync.handle,
+ *         .timeout_nsec = INT64_MAX,
+ *         .count_handles = 1,
+ *         .flags = 0,
+ *         .first_signaled = 0,
+ *         .pad = 0,
+ *     };
+ *     ioctl(fd, DRM_IOCTL_SYNCOBJ_WAIT, &wait);
+ */
+struct drm_xe_sync {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+#define DRM_XE_SYNC_TYPE_SYNCOBJ		0x0
+#define DRM_XE_SYNC_TYPE_TIMELINE_SYNCOBJ	0x1
+#define DRM_XE_SYNC_TYPE_USER_FENCE		0x2
+	/** @type: Type of the this sync object */
+	__u32 type;
+
+#define DRM_XE_SYNC_FLAG_SIGNAL	(1 << 0)
+	/** @flags: Sync Flags */
+	__u32 flags;
+
+	union {
+		/** @handle: Handle for the object */
+		__u32 handle;
+
+		/**
+		 * @addr: Address of user fence. When sync is passed in via exec
+		 * IOCTL this is a GPU address in the VM. When sync passed in via
+		 * VM bind IOCTL this is a user pointer. In either case, it is
+		 * the users responsibility that this address is present and
+		 * mapped when the user fence is signalled. Must be qword
+		 * aligned.
+		 */
+		__u64 addr;
+	};
+
+	/**
+	 * @timeline_value: Input for the timeline sync object. Needs to be
+	 * different than 0 when used with %DRM_XE_SYNC_FLAG_TIMELINE_SYNCOBJ.
+	 */
+	__u64 timeline_value;
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+/**
+ * struct drm_xe_exec - Input of &DRM_IOCTL_XE_EXEC
+ *
+ * This is an example to use @drm_xe_exec for execution of the object
+ * at BIND_ADDRESS (see example in @drm_xe_vm_bind) by an exec_queue
+ * (see example in @drm_xe_exec_queue_create). It can be synchronized
+ * by using the example provided for @drm_xe_sync.
+ *
+ * .. code-block:: C
+ *
+ *     struct drm_xe_exec exec = {
+ *         .exec_queue_id = exec_queue,
+ *         .syncs = &sync,
+ *         .num_syncs = 1,
+ *         .address = BIND_ADDRESS,
+ *         .num_batch_buffer = 1,
+ *     };
+ *     ioctl(fd, DRM_IOCTL_XE_EXEC, &exec);
+ *
+ */
+struct drm_xe_exec {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+	/** @exec_queue_id: Exec queue ID for the batch buffer */
+	__u32 exec_queue_id;
+
+	/** @num_syncs: Amount of struct drm_xe_sync in array. */
+	__u32 num_syncs;
+
+	/** @syncs: Pointer to struct drm_xe_sync array. */
+	__u64 syncs;
+
+	/**
+	 * @address: address of batch buffer if num_batch_buffer == 1 or an
+	 * array of batch buffer addresses
+	 */
+	__u64 address;
+
+	/**
+	 * @num_batch_buffer: number of batch buffer in this exec, must match
+	 * the width of the engine
+	 */
+	__u16 num_batch_buffer;
+
+	/** @pad: MBZ */
+	__u16 pad[3];
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+/**
+ * struct drm_xe_wait_user_fence - Input of &DRM_IOCTL_XE_WAIT_USER_FENCE
+ *
+ * Wait on user fence, XE will wake-up on every HW engine interrupt in the
+ * instances list and check if user fence is complete::
+ *
+ *	(*addr & MASK) OP (VALUE & MASK)
+ *
+ * Returns to user on user fence completion or timeout.
+ *
+ * The @op can be:
+ *  - %DRM_XE_UFENCE_WAIT_OP_EQ
+ *  - %DRM_XE_UFENCE_WAIT_OP_NEQ
+ *  - %DRM_XE_UFENCE_WAIT_OP_GT
+ *  - %DRM_XE_UFENCE_WAIT_OP_GTE
+ *  - %DRM_XE_UFENCE_WAIT_OP_LT
+ *  - %DRM_XE_UFENCE_WAIT_OP_LTE
+ *
+ * and the @flags can be:
+ *  - %DRM_XE_UFENCE_WAIT_FLAG_ABSTIME
+ *  - %DRM_XE_UFENCE_WAIT_FLAG_SOFT_OP
+ *
+ * The @mask values can be for example:
+ *  - 0xffu for u8
+ *  - 0xffffu for u16
+ *  - 0xffffffffu for u32
+ *  - 0xffffffffffffffffu for u64
+ */
+struct drm_xe_wait_user_fence {
+	/** @extensions: Pointer to the first extension struct, if any */
+	__u64 extensions;
+
+	/**
+	 * @addr: user pointer address to wait on, must qword aligned
+	 */
+	__u64 addr;
+
+#define DRM_XE_UFENCE_WAIT_OP_EQ	0x0
+#define DRM_XE_UFENCE_WAIT_OP_NEQ	0x1
+#define DRM_XE_UFENCE_WAIT_OP_GT	0x2
+#define DRM_XE_UFENCE_WAIT_OP_GTE	0x3
+#define DRM_XE_UFENCE_WAIT_OP_LT	0x4
+#define DRM_XE_UFENCE_WAIT_OP_LTE	0x5
+	/** @op: wait operation (type of comparison) */
+	__u16 op;
+
+#define DRM_XE_UFENCE_WAIT_FLAG_ABSTIME	(1 << 0)
+	/** @flags: wait flags */
+	__u16 flags;
+
+	/** @pad: MBZ */
+	__u32 pad;
+
+	/** @value: compare value */
+	__u64 value;
+
+	/** @mask: comparison mask */
+	__u64 mask;
+
+	/**
+	 * @timeout: how long to wait before bailing, value in nanoseconds.
+	 * Without DRM_XE_UFENCE_WAIT_FLAG_ABSTIME flag set (relative timeout)
+	 * it contains timeout expressed in nanoseconds to wait (fence will
+	 * expire at now() + timeout).
+	 * When DRM_XE_UFENCE_WAIT_FLAG_ABSTIME flat is set (absolute timeout) wait
+	 * will end at timeout (uses system MONOTONIC_CLOCK).
+	 * Passing negative timeout leads to neverending wait.
+	 *
+	 * On relative timeout this value is updated with timeout left
+	 * (for restarting the call in case of signal delivery).
+	 * On absolute timeout this value stays intact (restarted call still
+	 * expire at the same point of time).
+	 */
+	__s64 timeout;
+
+	/** @exec_queue_id: exec_queue_id returned from xe_exec_queue_create_ioctl */
+	__u32 exec_queue_id;
+
+	/** @pad2: MBZ */
+	__u32 pad2;
+
+	/** @reserved: Reserved */
+	__u64 reserved[2];
+};
+
+#define XE_TILING_NONE		0
+#define XE_TILING_X		1
+#define XE_TILING_Y		2
+#define XE_TILING_4		9
+#define XE_TILING_LAST	XE_TILING_4
+
+#if defined(__cplusplus)
+}
+#endif
+
+#endif /* _XE_DRM_H_ */
diff --git a/i915.c b/i915.c
index 995d930..adfd8c5 100644
--- a/i915.c
+++ b/i915.c
@@ -283,20 +283,16 @@ static int i915_add_combinations(struct driver *drv)
 	drv_add_combinations(drv, scanout_render_formats, ARRAY_SIZE(scanout_render_formats),
 			     &metadata_x_tiled, scanout_and_render_not_linear);
 
+	const uint64_t nv12_usage =
+	    BO_USE_TEXTURE | BO_USE_HW_VIDEO_DECODER | BO_USE_SCANOUT | hw_protected;
+	const uint64_t p010_usage = BO_USE_TEXTURE | BO_USE_HW_VIDEO_DECODER | hw_protected |
+				    (i915->graphics_version >= 11 ? BO_USE_SCANOUT : 0);
+
 	if (i915->is_mtl) {
 		struct format_metadata metadata_4_tiled = { .tiling = I915_TILING_4,
 							    .priority = 3,
 							    .modifier = I915_FORMAT_MOD_4_TILED };
-/* Support tile4 NV12 and P010 for libva */
-#ifdef I915_SCANOUT_4_TILED
-		const uint64_t nv12_usage =
-		    BO_USE_TEXTURE | BO_USE_HW_VIDEO_DECODER | BO_USE_SCANOUT | hw_protected;
-		const uint64_t p010_usage =
-		    BO_USE_TEXTURE | BO_USE_HW_VIDEO_DECODER | hw_protected | BO_USE_SCANOUT;
-#else
-		const uint64_t nv12_usage = BO_USE_TEXTURE | BO_USE_HW_VIDEO_DECODER;
-		const uint64_t p010_usage = nv12_usage;
-#endif
+
 		drv_add_combination(drv, DRM_FORMAT_NV12, &metadata_4_tiled, nv12_usage);
 		drv_add_combination(drv, DRM_FORMAT_P010, &metadata_4_tiled, p010_usage);
 		drv_add_combinations(drv, render_formats, ARRAY_SIZE(render_formats),
@@ -309,17 +305,6 @@ static int i915_add_combinations(struct driver *drv)
 							    .priority = 3,
 							    .modifier = I915_FORMAT_MOD_Y_TILED };
 
-/* Support y-tiled NV12 and P010 for libva */
-#ifdef I915_SCANOUT_Y_TILED
-		const uint64_t nv12_usage =
-		    BO_USE_TEXTURE | BO_USE_HW_VIDEO_DECODER | BO_USE_SCANOUT | hw_protected;
-		const uint64_t p010_usage = BO_USE_TEXTURE | BO_USE_HW_VIDEO_DECODER |
-					    hw_protected |
-					    (i915->graphics_version >= 11 ? BO_USE_SCANOUT : 0);
-#else
-		const uint64_t nv12_usage = BO_USE_TEXTURE | BO_USE_HW_VIDEO_DECODER;
-		const uint64_t p010_usage = nv12_usage;
-#endif
 		drv_add_combinations(drv, render_formats, ARRAY_SIZE(render_formats),
 				     &metadata_y_tiled, render_not_linear);
 		/* Y-tiled scanout isn't available on old platforms so we add
@@ -579,10 +564,9 @@ static size_t i915_num_planes_from_modifier(struct driver *drv, uint32_t format,
 static int i915_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t height, uint32_t format,
 				    uint64_t use_flags, const uint64_t *modifiers, uint32_t count)
 {
-	uint64_t modifier;
 	struct i915_device *i915 = bo->drv->priv;
-	bool huge_bo = (i915->graphics_version < 11) && (width > 4096);
 
+	uint64_t modifier;
 	if (modifiers) {
 		modifier =
 		    drv_pick_modifier(modifiers, count, i915->modifier.order, i915->modifier.count);
@@ -593,10 +577,32 @@ static int i915_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t heig
 		modifier = combo->metadata.modifier;
 	}
 
+	/*
+	 * For cursor buffer, add padding as needed to reach a known cursor-plane-supported
+	 * buffer size, as reported by the cursor capability properties.
+	 *
+	 * If the requested dimensions exceed either of the reported capabilities, or if the
+	 * capabilities couldn't be read, silently fallback by continuing without additional
+	 * padding. The buffer can still be used normally, and be committed to non-cursor
+	 * planes.
+	 */
+	if (use_flags & BO_USE_CURSOR) {
+		uint64_t cursor_width = 0;
+		uint64_t cursor_height = 0;
+		bool err = drmGetCap(bo->drv->fd, DRM_CAP_CURSOR_WIDTH, &cursor_width) ||
+			      drmGetCap(bo->drv->fd, DRM_CAP_CURSOR_HEIGHT, &cursor_height);
+
+		if (!err && width <= cursor_width && height <= cursor_height) {
+			width = cursor_width;
+			height = cursor_height;
+		}
+	}
+
 	/*
 	 * i915 only supports linear/x-tiled above 4096 wide on Gen9/Gen10 GPU.
 	 * VAAPI decode in NV12 Y tiled format so skip modifier change for NV12/P010 huge bo.
 	 */
+	bool huge_bo = (i915->graphics_version < 11) && (width > 4096);
 	if (huge_bo && format != DRM_FORMAT_NV12 && format != DRM_FORMAT_P010 &&
 	    modifier != I915_FORMAT_MOD_X_TILED && modifier != DRM_FORMAT_MOD_LINEAR) {
 		uint32_t i;
@@ -915,6 +921,21 @@ static int i915_bo_import(struct bo *bo, struct drv_import_fd_data *data)
 	return 0;
 }
 
+static bool use_write_combining(struct bo *bo)
+{
+	/* TODO(b/118799155): We don't seem to have a good way to
+	 * detect the use cases for which WC mapping is really needed.
+	 * The current heuristic seems overly coarse and may be slowing
+	 * down some other use cases unnecessarily.
+	 *
+	 * For now, care must be taken not to use WC mappings for
+	 * Renderscript and camera use cases, as they're
+	 * performance-sensitive. */
+	return (bo->meta.use_flags & BO_USE_SCANOUT) &&
+	       !(bo->meta.use_flags &
+		 (BO_USE_RENDERSCRIPT | BO_USE_CAMERA_READ | BO_USE_CAMERA_WRITE));
+}
+
 static void *i915_bo_map(struct bo *bo, struct vma *vma, uint32_t map_flags)
 {
 	int ret;
@@ -933,6 +954,9 @@ static void *i915_bo_map(struct bo *bo, struct vma *vma, uint32_t map_flags)
 			gem_map.handle = bo->handle.u32;
 			gem_map.flags = I915_MMAP_OFFSET_WB;
 
+			if (use_write_combining(bo))
+				gem_map.flags = I915_MMAP_OFFSET_WC;
+
 			/* Get the fake offset back */
 			ret = drmIoctl(bo->drv->fd, DRM_IOCTL_I915_GEM_MMAP_OFFSET, &gem_map);
 			if (ret == 0)
@@ -940,17 +964,7 @@ static void *i915_bo_map(struct bo *bo, struct vma *vma, uint32_t map_flags)
 					    MAP_SHARED, bo->drv->fd, gem_map.offset);
 		} else {
 			struct drm_i915_gem_mmap gem_map = { 0 };
-			/* TODO(b/118799155): We don't seem to have a good way to
-			 * detect the use cases for which WC mapping is really needed.
-			 * The current heuristic seems overly coarse and may be slowing
-			 * down some other use cases unnecessarily.
-			 *
-			 * For now, care must be taken not to use WC mappings for
-			 * Renderscript and camera use cases, as they're
-			 * performance-sensitive. */
-			if ((bo->meta.use_flags & BO_USE_SCANOUT) &&
-			    !(bo->meta.use_flags &
-			      (BO_USE_RENDERSCRIPT | BO_USE_CAMERA_READ | BO_USE_CAMERA_WRITE)))
+			if (use_write_combining(bo))
 				gem_map.flags = I915_MMAP_WC;
 
 			gem_map.handle = bo->handle.u32;
diff --git a/intel_defines.h b/intel_defines.h
new file mode 100644
index 0000000..bb00100
--- /dev/null
+++ b/intel_defines.h
@@ -0,0 +1,65 @@
+/*
+ * Copyright 2023 The Chromium OS Authors. All rights reserved.
+ * Use of this source code is governed by a BSD-style license that can be
+ * found in the LICENSE file.
+ */
+
+#define ARRAY_SIZE(A) (sizeof(A) / sizeof(*(A)))
+
+static const uint32_t scanout_render_formats[] = {
+	DRM_FORMAT_ABGR2101010,
+	DRM_FORMAT_ABGR8888,
+	DRM_FORMAT_ARGB2101010,
+	DRM_FORMAT_ARGB8888,
+	DRM_FORMAT_RGB565,
+	DRM_FORMAT_XBGR2101010,
+	DRM_FORMAT_XBGR8888,
+	DRM_FORMAT_XRGB2101010,
+	DRM_FORMAT_XRGB8888,
+};
+
+static const uint32_t render_formats[] = { DRM_FORMAT_ABGR16161616F, };
+
+static const uint32_t texture_only_formats[] = {
+	DRM_FORMAT_R8,
+	DRM_FORMAT_NV12,
+	DRM_FORMAT_P010,
+	DRM_FORMAT_YVU420,
+	DRM_FORMAT_YVU420_ANDROID,
+};
+
+static const uint64_t gen12_modifier_order[] = {
+	I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS,
+	I915_FORMAT_MOD_Y_TILED,
+	I915_FORMAT_MOD_X_TILED,
+	DRM_FORMAT_MOD_LINEAR,
+};
+
+static const uint64_t xe_lpdp_modifier_order[] = {
+	/* TODO(ryanneph): I915_FORMAT_MOD_4_TILED_MTL_RC_CCS, */
+	I915_FORMAT_MOD_4_TILED,
+	I915_FORMAT_MOD_X_TILED,
+	DRM_FORMAT_MOD_LINEAR,
+};
+
+const uint16_t gen12_ids[] = {
+	0x4c8a, 0x4c8b, 0x4c8c, 0x4c90, 0x4c9a, 0x4680, 0x4681, 0x4682, 0x4683, 0x4688,
+	0x4689, 0x4690, 0x4691, 0x4692, 0x4693, 0x4698, 0x4699, 0x4626, 0x4628, 0x462a,
+	0x46a0, 0x46a1, 0x46a2, 0x46a3, 0x46a6, 0x46a8, 0x46aa, 0x46b0, 0x46b1, 0x46b2,
+	0x46b3, 0x46c0, 0x46c1, 0x46c2, 0x46c3, 0x9A40, 0x9A49, 0x9A59, 0x9A60, 0x9A68,
+	0x9A70, 0x9A78, 0x9AC0, 0x9AC9, 0x9AD9, 0x9AF8, 0x4905, 0x4906, 0x4907, 0x4908,
+};
+
+const uint16_t adlp_ids[] = {
+	0x46A0, 0x46A1, 0x46A2, 0x46A3, 0x46A6, 0x46A8, 0x46AA,
+	0x462A, 0x4626, 0x4628, 0x46B0, 0x46B1, 0x46B2, 0x46B3,
+	0x46C0, 0x46C1, 0x46C2, 0x46C3, 0x46D0, 0x46D1, 0x46D2,
+};
+
+const uint16_t rplp_ids[] = { 0xA720, 0xA721, 0xA7A0, 0xA7A1, 0xA7A8, 0xA7A9, };
+
+const uint16_t mtl_ids[] = { 0x7D40, 0x7D60, 0x7D45, 0x7D55, 0x7DD5, };
+
+const uint16_t lnl_ids[] = { 0x6420, 0x64A0, 0x64B0, };
+
+const uint16_t ptl_ids[] = { 0xB080, 0xB081, 0xB082, 0xB083, 0xB08F, 0xB090, 0xB0A0, 0xB0B0 };
diff --git a/mediatek.c b/mediatek.c
index 4fbbc98..e34f672 100644
--- a/mediatek.c
+++ b/mediatek.c
@@ -387,6 +387,7 @@ static int mediatek_bo_create_with_modifiers(struct bo *bo, uint32_t width, uint
 			bo->meta.sizes[1] = bo->meta.sizes[1] * 10 / 16;
 			bo->meta.offsets[1] = bo->meta.sizes[0];
 			bo->meta.total_size = bo->meta.total_size * 10 / 16;
+			heap_data.len = bo->meta.total_size;
 		}
 
 		if (priv->dma_heap_fd < 0) {
diff --git a/util.h b/util.h
index aa1e79e..4e9a06a 100644
--- a/util.h
+++ b/util.h
@@ -15,5 +15,6 @@
 #define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
 #define STRINGIZE_NO_EXPANSION(x) #x
 #define STRINGIZE(x) STRINGIZE_NO_EXPANSION(x)
+#define BITFIELD_BIT(b) (1u<<(b))
 
 #endif
diff --git a/virtgpu_cross_domain.c b/virtgpu_cross_domain.c
index 1bba350..02e5f13 100644
--- a/virtgpu_cross_domain.c
+++ b/virtgpu_cross_domain.c
@@ -35,7 +35,7 @@ struct cross_domain_private {
 	uint32_t ring_handle;
 	void *ring_addr;
 	struct drv_array *metadata_cache;
-	pthread_mutex_t metadata_cache_lock;
+	pthread_mutex_t bo_create_lock;
 	bool mt8183_camera_quirk_;
 };
 
@@ -61,7 +61,7 @@ static void cross_domain_release_private(struct driver *drv)
 	if (priv->metadata_cache)
 		drv_array_destroy(priv->metadata_cache);
 
-	pthread_mutex_destroy(&priv->metadata_cache_lock);
+	pthread_mutex_destroy(&priv->bo_create_lock);
 
 	free(priv);
 }
@@ -155,14 +155,13 @@ static int cross_domain_metadata_query(struct driver *drv, struct bo_metadata *m
 	uint32_t plane;
 
 	memset(&cmd_get_reqs, 0, sizeof(cmd_get_reqs));
-	pthread_mutex_lock(&priv->metadata_cache_lock);
 	for (uint32_t i = 0; i < drv_array_size(priv->metadata_cache); i++) {
 		cached_data = (struct bo_metadata *)drv_array_at_idx(priv->metadata_cache, i);
 		if (!metadata_equal(metadata, cached_data))
 			continue;
 
 		memcpy(metadata, cached_data, sizeof(*cached_data));
-		goto out_unlock;
+		return 0;
 	}
 
 	cmd_get_reqs.hdr.cmd = CROSS_DOMAIN_CMD_GET_IMAGE_REQUIREMENTS;
@@ -192,7 +191,7 @@ static int cross_domain_metadata_query(struct driver *drv, struct bo_metadata *m
 	ret = cross_domain_submit_cmd(drv, (uint32_t *)&cmd_get_reqs, cmd_get_reqs.hdr.cmd_size,
 				      true);
 	if (ret < 0)
-		goto out_unlock;
+		return ret;
 
 	memcpy(&metadata->strides, &addr[0], 4 * sizeof(uint32_t));
 	memcpy(&metadata->offsets, &addr[4], 4 * sizeof(uint32_t));
@@ -211,10 +210,7 @@ static int cross_domain_metadata_query(struct driver *drv, struct bo_metadata *m
 	metadata->sizes[plane - 1] = metadata->total_size - metadata->offsets[plane - 1];
 
 	drv_array_append(priv->metadata_cache, metadata);
-
-out_unlock:
-	pthread_mutex_unlock(&priv->metadata_cache_lock);
-	return ret;
+	return 0;
 }
 
 /* Fill out metadata for guest buffers, used only for CPU access: */
@@ -264,7 +260,7 @@ static int cross_domain_init(struct driver *drv)
 	if (!priv)
 		return -ENOMEM;
 
-	ret = pthread_mutex_init(&priv->metadata_cache_lock, NULL);
+	ret = pthread_mutex_init(&priv->bo_create_lock, NULL);
 	if (ret) {
 		free(priv);
 		return ret;
@@ -367,8 +363,8 @@ static void cross_domain_close(struct driver *drv)
 	cross_domain_release_private(drv);
 }
 
-static int cross_domain_bo_create(struct bo *bo, uint32_t width, uint32_t height, uint32_t format,
-				  uint64_t use_flags)
+static int cross_domain_bo_create_locked(struct bo *bo, uint32_t width, uint32_t height,
+					 uint32_t format, uint64_t use_flags)
 {
 	int ret;
 	uint32_t blob_flags = VIRTGPU_BLOB_FLAG_USE_SHAREABLE;
@@ -418,6 +414,29 @@ static int cross_domain_bo_create(struct bo *bo, uint32_t width, uint32_t height
 	return 0;
 }
 
+static int cross_domain_bo_create(struct bo *bo, uint32_t width, uint32_t height, uint32_t format,
+				  uint64_t use_flags)
+{
+
+	int ret = 0;
+	struct cross_domain_private *priv = bo->drv->priv;
+
+	// HACK(b/395748805): Any host GET_IMAGE_REQUIREMENTS request must be immediately followed
+	// by the matching CREATE_BLOB request, as the current implementation in crosvm stashes a
+	// single buffer allocation for the first to be returned by the second. We ensure the two
+	// requests are made back to back by using a mutex lock, where the lock is acquired for the
+	// duration of the allocation requests.
+	//
+	// This forces all guest allocations to be made in serial order, and allows the host buffer
+	// stash to be an optimization.
+	pthread_mutex_lock(&priv->bo_create_lock);
+
+	ret = cross_domain_bo_create_locked(bo, width, height, format, use_flags);
+
+	pthread_mutex_unlock(&priv->bo_create_lock);
+	return ret;
+}
+
 static void *cross_domain_bo_map(struct bo *bo, struct vma *vma, uint32_t map_flags)
 {
 	int ret;
diff --git a/xe.c b/xe.c
new file mode 100644
index 0000000..c265c30
--- /dev/null
+++ b/xe.c
@@ -0,0 +1,746 @@
+/*
+ * Copyright 2024 The Chromium OS Authors. All rights reserved.
+ * Use of this source code is governed by a BSD-style license that can be
+ * found in the LICENSE file.
+ */
+
+#ifdef DRV_XE
+
+#include <assert.h>
+#include <errno.h>
+#include <stdbool.h>
+#include <stdio.h>
+#include <string.h>
+#include <sys/mman.h>
+#include <unistd.h>
+#include <xf86drm.h>
+
+#include "drv_helpers.h"
+#include "drv_priv.h"
+
+#include "external/xe_drm.h"
+#include "util.h"
+#include "intel_defines.h"
+
+struct modifier_support_t {
+	const uint64_t *order;
+	uint32_t count;
+};
+
+struct xe_device {
+	uint32_t graphics_version;
+	int device_id;
+	bool is_xelpd;
+	/*TODO : cleanup is_mtl_or_newer to avoid adding variables for every new platforms */
+	bool is_mtl_or_newer;
+	int32_t has_hw_protection;
+	bool has_local_mem;
+	int revision;
+
+	uint64_t gtt_size;
+	/**
+	  * Memory vm bind alignment and buffer size requirement
+	  */
+
+	unsigned mem_alignment;
+	struct modifier_support_t modifier;
+	int32_t num_fences_avail;
+	bool has_mmap_offset;
+};
+
+static void xe_info_from_device_id(struct xe_device *xe)
+{
+	unsigned i;
+	xe->graphics_version = 0;
+	xe->is_xelpd = false;
+	xe->is_mtl_or_newer = false;
+
+	/* search lists from most-->least specific */
+	for (i = 0; i < ARRAY_SIZE(adlp_ids); i++) {
+		if (adlp_ids[i] == xe->device_id) {
+			xe->is_xelpd = true;
+			xe->graphics_version = 12;
+			return;
+		}
+	}
+
+	for (i = 0; i < ARRAY_SIZE(rplp_ids); i++) {
+		if (rplp_ids[i] == xe->device_id) {
+			xe->is_xelpd = true;
+			xe->graphics_version = 12;
+			return;
+		}
+	}
+
+	for (i = 0; i < ARRAY_SIZE(mtl_ids); i++) {
+		if (mtl_ids[i] == xe->device_id) {
+			xe->graphics_version = 12;
+			xe->is_mtl_or_newer = true;
+			return;
+		}
+	}
+
+	for (i = 0; i < ARRAY_SIZE(lnl_ids); i++) {
+		if (lnl_ids[i] == xe->device_id) {
+			xe->graphics_version = 20;
+			xe->is_mtl_or_newer = true;
+			return;
+		}
+	}
+
+	for (i = 0; i < ARRAY_SIZE(ptl_ids); i++) {
+		if (ptl_ids[i] == xe->device_id) {
+			xe->graphics_version = 30;
+			xe->is_mtl_or_newer = true;
+			return;
+		}
+	}
+
+	/* Gen 12 */
+	for (i = 0; i < ARRAY_SIZE(gen12_ids); i++) {
+		if (gen12_ids[i] == xe->device_id) {
+			xe->graphics_version = 12;
+			return;
+		}
+	}
+}
+
+static void xe_get_modifier_order(struct xe_device *xe)
+{
+	if (xe->is_mtl_or_newer) {
+		xe->modifier.order = xe_lpdp_modifier_order;
+		xe->modifier.count = ARRAY_SIZE(xe_lpdp_modifier_order);
+	} else if (xe->is_xelpd) {
+		xe->modifier.order = gen12_modifier_order;
+		xe->modifier.count = ARRAY_SIZE(gen12_modifier_order);
+	} else {
+		xe->modifier.order = xe_lpdp_modifier_order;
+		xe->modifier.count = ARRAY_SIZE(xe_lpdp_modifier_order);
+	}
+}
+
+static uint64_t unset_flags(uint64_t current_flags, uint64_t mask)
+{
+	uint64_t value = current_flags & ~mask;
+	return value;
+}
+
+/* TODO(ryanneph): share implementation with i915_add_combinations */
+static int xe_add_combinations(struct driver *drv)
+{
+	struct xe_device *xe = drv->priv;
+
+	const uint64_t scanout_and_render = BO_USE_RENDER_MASK | BO_USE_SCANOUT;
+	const uint64_t render = BO_USE_RENDER_MASK;
+	const uint64_t texture_only = BO_USE_TEXTURE_MASK;
+	// HW protected buffers also need to be scanned out.
+	const uint64_t hw_protected =
+		xe->has_hw_protection ? (BO_USE_PROTECTED | BO_USE_SCANOUT) : 0;
+
+	const uint64_t linear_mask = BO_USE_RENDERSCRIPT | BO_USE_LINEAR | BO_USE_SW_READ_OFTEN |
+				     BO_USE_SW_WRITE_OFTEN | BO_USE_SW_READ_RARELY |
+				     BO_USE_SW_WRITE_RARELY;
+
+	struct format_metadata metadata_linear = { .tiling = XE_TILING_NONE,
+						   .priority = 1,
+						   .modifier = DRM_FORMAT_MOD_LINEAR };
+
+	drv_add_combinations(drv, scanout_render_formats, ARRAY_SIZE(scanout_render_formats),
+			     &metadata_linear, scanout_and_render);
+
+	drv_add_combinations(drv, render_formats, ARRAY_SIZE(render_formats), &metadata_linear,
+			     render);
+
+	drv_add_combinations(drv, texture_only_formats, ARRAY_SIZE(texture_only_formats),
+			     &metadata_linear, texture_only);
+
+	drv_modify_linear_combinations(drv);
+
+	/* NV12 format for camera, display, decoding and encoding. */
+	/* IPU3 camera ISP supports only NV12 output. */
+	drv_modify_combination(drv, DRM_FORMAT_NV12, &metadata_linear,
+			       BO_USE_CAMERA_READ | BO_USE_CAMERA_WRITE | BO_USE_SCANOUT |
+				   BO_USE_HW_VIDEO_DECODER | BO_USE_HW_VIDEO_ENCODER |
+				   hw_protected);
+
+	/* P010 linear can be used for scanout too. */
+	drv_modify_combination(drv, DRM_FORMAT_P010, &metadata_linear, BO_USE_SCANOUT);
+
+	/*
+	 * Android also frequently requests YV12 formats for some camera implementations
+	 * (including the external provider implementation).
+	 */
+	drv_modify_combination(drv, DRM_FORMAT_YVU420_ANDROID, &metadata_linear,
+			       BO_USE_CAMERA_WRITE);
+
+	/* Android CTS tests require this. */
+	drv_add_combination(drv, DRM_FORMAT_BGR888, &metadata_linear, BO_USE_SW_MASK);
+
+	/*
+	 * R8 format is used for Android's HAL_PIXEL_FORMAT_BLOB and is used for JPEG snapshots
+	 * from camera and input/output from hardware decoder/encoder.
+	 */
+	drv_modify_combination(drv, DRM_FORMAT_R8, &metadata_linear,
+			       BO_USE_CAMERA_READ | BO_USE_CAMERA_WRITE | BO_USE_HW_VIDEO_DECODER |
+				   BO_USE_HW_VIDEO_ENCODER | BO_USE_GPU_DATA_BUFFER |
+				   BO_USE_SENSOR_DIRECT_DATA);
+
+	const uint64_t render_not_linear = unset_flags(render, linear_mask);
+	const uint64_t scanout_and_render_not_linear = render_not_linear | BO_USE_SCANOUT;
+	struct format_metadata metadata_x_tiled = { .tiling = XE_TILING_X,
+						    .priority = 2,
+						    .modifier = I915_FORMAT_MOD_X_TILED };
+
+	drv_add_combinations(drv, render_formats, ARRAY_SIZE(render_formats), &metadata_x_tiled,
+			     render_not_linear);
+	drv_add_combinations(drv, scanout_render_formats, ARRAY_SIZE(scanout_render_formats),
+			     &metadata_x_tiled, scanout_and_render_not_linear);
+
+	const uint64_t nv12_usage =
+	    BO_USE_TEXTURE | BO_USE_HW_VIDEO_DECODER | BO_USE_SCANOUT | hw_protected;
+	const uint64_t p010_usage = BO_USE_TEXTURE | BO_USE_HW_VIDEO_DECODER | hw_protected |
+				    (xe->graphics_version >= 11 ? BO_USE_SCANOUT : 0);
+
+	if (xe->is_mtl_or_newer) {
+		struct format_metadata metadata_4_tiled = { .tiling = XE_TILING_4,
+							    .priority = 3,
+							    .modifier = I915_FORMAT_MOD_4_TILED };
+
+		drv_add_combination(drv, DRM_FORMAT_NV12, &metadata_4_tiled, nv12_usage);
+		drv_add_combination(drv, DRM_FORMAT_P010, &metadata_4_tiled, p010_usage);
+		drv_add_combinations(drv, render_formats, ARRAY_SIZE(render_formats),
+				     &metadata_4_tiled, render_not_linear);
+		drv_add_combinations(drv, scanout_render_formats,
+				     ARRAY_SIZE(scanout_render_formats), &metadata_4_tiled,
+				     scanout_and_render_not_linear);
+	} else {
+		struct format_metadata metadata_y_tiled = { .tiling = XE_TILING_Y,
+							    .priority = 3,
+							    .modifier = I915_FORMAT_MOD_Y_TILED };
+
+		drv_add_combinations(drv, render_formats, ARRAY_SIZE(render_formats),
+				     &metadata_y_tiled, render_not_linear);
+		drv_add_combinations(drv, scanout_render_formats,
+				     ARRAY_SIZE(scanout_render_formats), &metadata_y_tiled,
+				     scanout_and_render_not_linear);
+		drv_add_combination(drv, DRM_FORMAT_NV12, &metadata_y_tiled, nv12_usage);
+		drv_add_combination(drv, DRM_FORMAT_P010, &metadata_y_tiled, p010_usage);
+	}
+	return 0;
+}
+
+static int xe_align_dimensions(struct bo *bo, uint32_t format, uint32_t tiling, uint32_t *stride,
+				 uint32_t *aligned_height)
+{
+	uint32_t horizontal_alignment = 0;
+	uint32_t vertical_alignment = 0;
+
+	switch (tiling) {
+	default:
+	case XE_TILING_NONE:
+		/*
+		 * The Intel GPU doesn't need any alignment in linear mode,
+		 * but libva requires the allocation stride to be aligned to
+		 * 16 bytes and height to 4 rows. Further, we round up the
+		 * horizontal alignment so that row start on a cache line (64
+		 * bytes).
+		 */
+#ifdef LINEAR_ALIGN_256
+		/*
+		 * If we want to import these buffers to amdgpu they need to
+		 * their match LINEAR_ALIGNED requirement of 256 byte alignment.
+		 */
+		horizontal_alignment = 256;
+#else
+		horizontal_alignment = 64;
+#endif
+		/*
+		 * For hardware video encoding buffers, we want to align to the size of a
+		 * macroblock, because otherwise we will end up encoding uninitialized data.
+		 * This can result in substantial quality degradations, especially on lower
+		 * resolution videos, because this uninitialized data may be high entropy.
+		 * For R8 and height=1, we assume the surface will be used as a linear buffer blob
+		 * (such as VkBuffer). The hardware allows vertical_alignment=1 only for non-tiled
+		 * 1D surfaces, which covers the VkBuffer case. However, if the app uses the surface
+		 * as a 2D image with height=1, then this code is buggy. For 2D images, the hardware
+		 * requires a vertical_alignment >= 4, and underallocating with vertical_alignment=1
+		 * will cause the GPU to read out-of-bounds.
+		 *
+		 * TODO: add a new DRM_FORMAT_BLOB format for this case, or further tighten up the
+		 * constraints with GPU_DATA_BUFFER usage when the guest has migrated to use
+		 * virtgpu_cross_domain backend which passes that flag through.
+		 */
+		if (bo->meta.use_flags & BO_USE_HW_VIDEO_ENCODER) {
+			vertical_alignment = 8;
+		} else if (format == DRM_FORMAT_R8 && *aligned_height == 1)
+			vertical_alignment = 1;
+		else
+			vertical_alignment = 4;
+
+		break;
+	case XE_TILING_X:
+		horizontal_alignment = 512;
+		vertical_alignment = 8;
+		break;
+
+	case XE_TILING_Y:
+	case XE_TILING_4:
+		horizontal_alignment = 128;
+		vertical_alignment = 32;
+		break;
+	}
+
+	*aligned_height = ALIGN(*aligned_height, vertical_alignment);
+	*stride = ALIGN(*stride, horizontal_alignment);
+
+	return 0;
+}
+
+static bool xe_query_config(struct driver *drv, struct xe_device *xe)
+{
+	struct drm_xe_device_query query = {
+		.query = DRM_XE_DEVICE_QUERY_CONFIG,
+	};
+	if(drmIoctl(drv->fd, DRM_IOCTL_XE_DEVICE_QUERY, &query))
+		return false;
+
+	struct drm_xe_query_config *config = calloc(1, query.size);
+	if(!config)
+		return false;
+
+	query.data = (uintptr_t)config;
+	if(drmIoctl(drv->fd, DRM_IOCTL_XE_DEVICE_QUERY, &query))
+		goto data_query_failed;
+
+
+	if(config->info[DRM_XE_QUERY_CONFIG_FLAGS] & DRM_XE_QUERY_CONFIG_FLAG_HAS_VRAM)
+		xe->has_local_mem = true;
+	else
+		xe->has_local_mem = false;
+
+	xe->revision = (config->info[DRM_XE_QUERY_CONFIG_REV_AND_DEVICE_ID] >> 16) & 0xFFFF;
+	xe->gtt_size = 1ull << config->info[DRM_XE_QUERY_CONFIG_VA_BITS];
+	xe->mem_alignment = config->info[DRM_XE_QUERY_CONFIG_MIN_ALIGNMENT];
+
+	free(config);
+	return true;
+
+data_query_failed:
+	free(config);
+	return false;
+}
+
+static bool xe_device_probe(struct driver *drv, struct xe_device *xe)
+{
+	/* Retrieve the device info by querying KMD through IOCTL
+	*/
+	struct drm_xe_device_query query = {
+		.extensions = 0,
+		.query = DRM_XE_DEVICE_QUERY_CONFIG,
+		.size = 0,
+		.data = 0,
+	};
+
+	if(drmIoctl(drv->fd, DRM_IOCTL_XE_DEVICE_QUERY, &query))
+		return false;
+
+	struct drm_xe_query_config *config = calloc(1, query.size);
+	if(!config)
+		return false;
+
+	query.data = (uintptr_t)config;
+	if(drmIoctl(drv->fd, DRM_IOCTL_XE_DEVICE_QUERY, &query)){
+		free(config);
+		return false;
+	}
+
+	xe->device_id = ((config->info[DRM_XE_QUERY_CONFIG_REV_AND_DEVICE_ID] << 16)>>16) & 0xFFFF;
+	xe->revision = (config->info[DRM_XE_QUERY_CONFIG_REV_AND_DEVICE_ID] >> 16) & 0xFFFF;
+
+	free(config);
+	return true;
+}
+
+static int xe_init(struct driver *drv)
+{
+	struct xe_device *xe;
+
+	xe = calloc(1, sizeof(*xe));
+	if (!xe)
+		return -ENOMEM;
+
+	if(!xe_device_probe(drv, xe)){
+		drv_loge("Failed to query device id using DRM_IOCTL_XE_DEVICE_QUERY");
+		return -EINVAL;
+	}
+
+	xe_query_config(drv, xe);
+
+	/* must call before xe->graphics_version is used anywhere else */
+	xe_info_from_device_id(xe);
+
+	xe_get_modifier_order(xe);
+
+	/* Xe still don't have support for protected content */
+	if (xe->graphics_version >= 12)
+		xe->has_hw_protection = 0;
+	else if (xe->graphics_version < 12) {
+		drv_loge("Xe driver is not supported on your platform: 0x%x\n",xe->device_id);
+		return -errno;
+	}
+
+	drv->priv = xe;
+
+	return xe_add_combinations(drv);
+return 0;
+}
+
+/*
+ * Returns true if the height of a buffer of the given format should be aligned
+ * to the largest coded unit (LCU) assuming that it will be used for video. This
+ * is based on gmmlib's GmmIsYUVFormatLCUAligned().
+ */
+static bool xe_format_needs_LCU_alignment(uint32_t format, size_t plane,
+					    const struct xe_device *xe)
+{
+	switch (format) {
+	case DRM_FORMAT_NV12:
+	case DRM_FORMAT_P010:
+	case DRM_FORMAT_P016:
+		return (xe->graphics_version >= 12) && plane == 1;
+	}
+	return false;
+}
+
+static int xe_bo_from_format(struct bo *bo, uint32_t width, uint32_t height, uint32_t format)
+{
+	uint32_t offset;
+	size_t plane;
+	int ret, pagesize;
+	struct xe_device *xe = bo->drv->priv;
+
+	offset = 0;
+	pagesize = getpagesize();
+
+	for (plane = 0; plane < drv_num_planes_from_format(format); plane++) {
+		uint32_t stride = drv_stride_from_format(format, width, plane);
+		uint32_t plane_height = drv_height_from_format(format, height, plane);
+
+		if (bo->meta.tiling != XE_TILING_NONE)
+			assert(IS_ALIGNED(offset, pagesize));
+
+		ret = xe_align_dimensions(bo, format, bo->meta.tiling, &stride, &plane_height);
+		if (ret)
+			return ret;
+
+		if (xe_format_needs_LCU_alignment(format, plane, xe)) {
+			/*
+			 * Align the height of the V plane for certain formats to the
+			 * largest coded unit (assuming that this BO may be used for video)
+			 * to be consistent with gmmlib.
+			 */
+			plane_height = ALIGN(plane_height, 64);
+		}
+
+		bo->meta.strides[plane] = stride;
+		bo->meta.sizes[plane] = stride * plane_height;
+		bo->meta.offsets[plane] = offset;
+		offset += bo->meta.sizes[plane];
+	}
+
+	bo->meta.total_size = ALIGN(offset, pagesize);
+
+	return 0;
+}
+
+static size_t xe_num_planes_from_modifier(struct driver *drv, uint32_t format, uint64_t modifier)
+{
+	size_t num_planes = drv_num_planes_from_format(format);
+
+	if (modifier == I915_FORMAT_MOD_Y_TILED_CCS ||
+	    modifier == I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS) {
+		assert(num_planes == 1);
+		return 2;
+	}
+
+	return num_planes;
+}
+
+static int xe_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t height, uint32_t format,
+				    uint64_t use_flags, const uint64_t *modifiers, uint32_t count)
+{
+	int ret = 0;
+	uint64_t modifier;
+	struct xe_device *xe = bo->drv->priv;
+
+	if (modifiers) {
+		modifier =
+		    drv_pick_modifier(modifiers, count, xe->modifier.order, xe->modifier.count);
+	} else {
+		struct combination *combo = drv_get_combination(bo->drv, format, use_flags);
+		if (!combo)
+			return -EINVAL;
+
+		if ((xe->is_mtl_or_newer) &&
+		    (use_flags == (BO_USE_SCANOUT | BO_USE_TEXTURE | BO_USE_HW_VIDEO_DECODER))) {
+			modifier = I915_FORMAT_MOD_4_TILED;
+		} else {
+			modifier = combo->metadata.modifier;
+		}
+	}
+
+	/*
+	 * Skip I915_FORMAT_MOD_Y_TILED_CCS modifier if compression is disabled
+	 * Pick y tiled modifier if it has been passed in, otherwise use linear
+	 */
+	if (!bo->drv->compression && modifier == I915_FORMAT_MOD_Y_TILED_CCS) {
+		uint32_t i;
+		for (i = 0; modifiers && i < count; i++) {
+			if (modifiers[i] == I915_FORMAT_MOD_Y_TILED)
+				break;
+		}
+		if (i == count)
+			modifier = DRM_FORMAT_MOD_LINEAR;
+		else
+			modifier = I915_FORMAT_MOD_Y_TILED;
+	}
+
+	switch (modifier) {
+	case DRM_FORMAT_MOD_LINEAR:
+		bo->meta.tiling = XE_TILING_NONE;
+		break;
+	case I915_FORMAT_MOD_X_TILED:
+		bo->meta.tiling = XE_TILING_X;
+		break;
+	case I915_FORMAT_MOD_Y_TILED:
+	case I915_FORMAT_MOD_Y_TILED_CCS:
+	/* For now support only I915_TILING_Y as this works with all
+	 * IPs(render/media/display)
+	 */
+	case I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS:
+		bo->meta.tiling = XE_TILING_Y;
+		break;
+	case I915_FORMAT_MOD_4_TILED:
+		bo->meta.tiling = XE_TILING_4;
+		break;
+	}
+
+	bo->meta.format_modifier = modifier;
+
+	if (format == DRM_FORMAT_YVU420_ANDROID) {
+		/*
+		 * We only need to be able to use this as a linear texture,
+		 * which doesn't put any HW restrictions on how we lay it
+		 * out. The Android format does require the stride to be a
+		 * multiple of 16 and expects the Cr and Cb stride to be
+		 * ALIGN(Y_stride / 2, 16), which we can make happen by
+		 * aligning to 32 bytes here.
+		 */
+		uint32_t stride = ALIGN(width, 32);
+		ret = drv_bo_from_format(bo, stride, 1, height, format);
+		bo->meta.total_size = ALIGN(bo->meta.total_size, getpagesize());
+	} else if (modifier == I915_FORMAT_MOD_Y_TILED_CCS) {
+		/*
+		 * For compressed surfaces, we need a color control surface
+		 * (CCS). Color compression is only supported for Y tiled
+		 * surfaces, and for each 32x16 tiles in the main surface we
+		 * need a tile in the control surface.  Y tiles are 128 bytes
+		 * wide and 32 lines tall and we use that to first compute the
+		 * width and height in tiles of the main surface. stride and
+		 * height are already multiples of 128 and 32, respectively:
+		 */
+		uint32_t stride = drv_stride_from_format(format, width, 0);
+		uint32_t width_in_tiles = DIV_ROUND_UP(stride, 128);
+		uint32_t height_in_tiles = DIV_ROUND_UP(height, 32);
+		uint32_t size = width_in_tiles * height_in_tiles * 4096;
+		uint32_t offset = 0;
+
+		bo->meta.strides[0] = width_in_tiles * 128;
+		bo->meta.sizes[0] = size;
+		bo->meta.offsets[0] = offset;
+		offset += size;
+
+		/*
+		 * Now, compute the width and height in tiles of the control
+		 * surface by dividing and rounding up.
+		 */
+		uint32_t ccs_width_in_tiles = DIV_ROUND_UP(width_in_tiles, 32);
+		uint32_t ccs_height_in_tiles = DIV_ROUND_UP(height_in_tiles, 16);
+		uint32_t ccs_size = ccs_width_in_tiles * ccs_height_in_tiles * 4096;
+
+		/*
+		 * With stride and height aligned to y tiles, offset is
+		 * already a multiple of 4096, which is the required alignment
+		 * of the CCS.
+		 */
+		bo->meta.strides[1] = ccs_width_in_tiles * 128;
+		bo->meta.sizes[1] = ccs_size;
+		bo->meta.offsets[1] = offset;
+		offset += ccs_size;
+
+		bo->meta.num_planes = xe_num_planes_from_modifier(bo->drv, format, modifier);
+		bo->meta.total_size = offset;
+	} else if (modifier == I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS) {
+		/*
+		 * considering only 128 byte compression and one cache line of
+		 * aux buffer(64B) contains compression status of 4-Y tiles.
+		 * Which is 4 * (128B * 32L).
+		 * line stride(bytes) is 4 * 128B
+		 * and tile stride(lines) is 32L
+		 */
+		uint32_t stride = ALIGN(drv_stride_from_format(format, width, 0), 512);
+
+		height = ALIGN(drv_height_from_format(format, height, 0), 32);
+
+		if (xe->is_xelpd && (stride > 1)) {
+			stride = 1 << (32 - __builtin_clz(stride - 1));
+			height = ALIGN(drv_height_from_format(format, height, 0), 128);
+		}
+
+		bo->meta.strides[0] = stride;
+		/* size calculation and alignment are 64KB aligned
+		 * size as per spec
+		 */
+		bo->meta.sizes[0] = ALIGN(stride * height, 65536);
+		bo->meta.offsets[0] = 0;
+
+		/* Aux buffer is linear and page aligned. It is placed after
+		 * other planes and aligned to main buffer stride.
+		 */
+		bo->meta.strides[1] = bo->meta.strides[0] / 8;
+		/* Aligned to page size */
+		bo->meta.sizes[1] = ALIGN(bo->meta.sizes[0] / 256, getpagesize());
+		bo->meta.offsets[1] = bo->meta.sizes[0];
+		/* Total number of planes & sizes */
+		bo->meta.num_planes = xe_num_planes_from_modifier(bo->drv, format, modifier);
+		bo->meta.total_size = bo->meta.sizes[0] + bo->meta.sizes[1];
+	} else {
+		ret = xe_bo_from_format(bo, width, height, format);
+	}
+
+	return ret;
+}
+
+static int xe_bo_create_from_metadata(struct bo *bo)
+{
+	int ret;
+
+	uint32_t flags = 0;
+	uint32_t cpu_caching;
+	if (bo->meta.use_flags & BO_USE_SCANOUT) {
+		flags |= DRM_XE_GEM_CREATE_FLAG_SCANOUT;
+		cpu_caching = DRM_XE_GEM_CPU_CACHING_WC;
+	} else {
+		cpu_caching = DRM_XE_GEM_CPU_CACHING_WB;
+	}
+
+	struct drm_xe_gem_create gem_create = {
+	     .vm_id = 0, /* ensure exportable to PRIME fd */
+	     .size = bo->meta.total_size,
+	     .flags = flags,
+	     .cpu_caching = cpu_caching,
+	};
+
+	/* FIXME: let's assume iGPU with SYSMEM is only supported */
+	gem_create.placement |= BITFIELD_BIT(DRM_XE_MEM_REGION_CLASS_SYSMEM);
+
+	ret = drmIoctl(bo->drv->fd, DRM_IOCTL_XE_GEM_CREATE, &gem_create);
+	if (ret)
+		return -errno;
+
+	bo->handle.u32 = gem_create.handle;
+
+	return 0;
+}
+
+static void xe_close(struct driver *drv)
+{
+	free(drv->priv);
+	drv->priv = NULL;
+}
+
+static int xe_bo_import(struct bo *bo, struct drv_import_fd_data *data)
+{
+	int ret;
+
+	bo->meta.num_planes =
+	    xe_num_planes_from_modifier(bo->drv, data->format, data->format_modifier);
+
+	ret = drv_prime_bo_import(bo, data);
+	if (ret)
+		return ret;
+
+	return 0;
+}
+
+static void *xe_bo_map(struct bo *bo, struct vma *vma, uint32_t map_flags)
+{
+	int ret;
+	void *addr = MAP_FAILED;
+
+	struct drm_xe_gem_mmap_offset gem_map = {
+		.handle = bo->handle.u32,
+	};
+
+	/* Get the fake offset back */
+	ret = drmIoctl(bo->drv->fd, DRM_IOCTL_XE_GEM_MMAP_OFFSET, &gem_map);
+	if (ret == 0) {
+		addr = mmap(0, bo->meta.total_size, PROT_READ | PROT_WRITE,
+			    MAP_SHARED, bo->drv->fd, gem_map.offset);
+	}
+
+	if (addr == MAP_FAILED) {
+		drv_loge("xe GEM mmap failed\n");
+		return addr;
+	}
+
+	vma->length = bo->meta.total_size;
+
+	return addr;
+}
+
+#define XE_CACHELINE_SIZE 64
+#define XE_CACHELINE_MASK (XE_CACHELINE_SIZE - 1)
+static void xe_clflush(void *start, size_t size)
+{
+	/* copy of i915_clflush() */
+	void *p = (void *)(((uintptr_t)start) & ~XE_CACHELINE_MASK);
+	void *end = (void *)((uintptr_t)start + size);
+
+	__builtin_ia32_mfence();
+	while (p < end) {
+#if defined(__CLFLUSHOPT__)
+		__builtin_ia32_clflushopt(p);
+#else
+		__builtin_ia32_clflush(p);
+#endif
+		p = (void *)((uintptr_t)p + XE_CACHELINE_SIZE);
+	}
+	__builtin_ia32_mfence();
+}
+
+static int xe_bo_flush(struct bo *bo, struct mapping *mapping)
+{
+	if (bo->meta.tiling == XE_TILING_NONE) {
+		xe_clflush(mapping->vma->addr, mapping->vma->length);
+	}
+
+	return 0;
+}
+
+const struct backend backend_xe = {
+	.name = "xe",
+	.init = xe_init,
+	.close = xe_close,
+	.bo_compute_metadata = xe_bo_compute_metadata,
+	.bo_create_from_metadata = xe_bo_create_from_metadata,
+	.bo_map = xe_bo_map,
+	.bo_destroy = drv_gem_bo_destroy,
+	.bo_unmap = drv_bo_munmap,
+	.num_planes_from_modifier = xe_num_planes_from_modifier,
+	.bo_import = xe_bo_import,
+	.bo_flush = xe_bo_flush,
+	.resolve_format_and_use_flags = drv_resolve_format_and_use_flags_helper,
+};
+
+#endif
```

