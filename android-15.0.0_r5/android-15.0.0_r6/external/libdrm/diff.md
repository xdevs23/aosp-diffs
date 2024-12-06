```diff
diff --git a/.gitlab-ci.yml b/.gitlab-ci.yml
index c5aa7a2b..2c234314 100644
--- a/.gitlab-ci.yml
+++ b/.gitlab-ci.yml
@@ -12,7 +12,7 @@
 # main repository, it's recommended to remove the image from the source
 # repository's container registry, so that the image from the main
 # repository's registry will be used there as well.
-.templates_sha: &template_sha 567700e483aabed992d0a4fea84994a0472deff6 # see https://docs.gitlab.com/ee/ci/yaml/#includefile
+.templates_sha: &template_sha b61a03cabbf308e81289f7aaaf0b5a80a34ffb99 # see https://docs.gitlab.com/ee/ci/yaml/#includefile
 
 include:
   - project: 'freedesktop/ci-templates'
@@ -39,12 +39,11 @@ stages:
 .os-debian:
   variables:
     BUILD_OS: debian
-    FDO_DISTRIBUTION_VERSION: buster
+    FDO_DISTRIBUTION_VERSION: bookworm
     FDO_DISTRIBUTION_PACKAGES: 'build-essential docbook-xsl libatomic-ops-dev libcairo2-dev libcunit1-dev libpciaccess-dev meson ninja-build pkg-config python3 python3-pip python3-wheel python3-setuptools python3-docutils valgrind'
-    FDO_DISTRIBUTION_EXEC: 'pip3 install meson==0.53.0'
     # bump this tag every time you change something which requires rebuilding the
     # base image
-    FDO_DISTRIBUTION_TAG: "2022-01-19.0"
+    FDO_DISTRIBUTION_TAG: "2024-06-25.0"
 
 .debian-x86_64:
   extends:
@@ -67,11 +66,11 @@ stages:
 .os-freebsd:
   variables:
     BUILD_OS: freebsd
-    FDO_DISTRIBUTION_VERSION: "13.0"
-    FDO_DISTRIBUTION_PACKAGES: 'meson ninja pkgconf libpciaccess libpthread-stubs py38-docutils cairo'
+    FDO_DISTRIBUTION_VERSION: "14.1"
+    FDO_DISTRIBUTION_PACKAGES: 'meson ninja pkgconf libpciaccess py39-docutils cairo'
     # bump this tag every time you change something which requires rebuilding the
     # base image
-    FDO_DISTRIBUTION_TAG: "2021-11-10.1"
+    FDO_DISTRIBUTION_TAG: "2026-26-25.0"
 
 .freebsd-x86_64:
   extends:
@@ -205,9 +204,6 @@ x86_64-freebsd-container_prep:
         -D radeon=true
         -D tegra=true
         -D udev=true
-        -D valgrind=auto
-        -D vc4=true
-        -D vmwgfx=true
     - ninja -C build
     - ninja -C build test
     - DESTDIR=$PWD/install ninja -C build install
diff --git a/.gitlab-ci/debian-install.sh b/.gitlab-ci/debian-install.sh
deleted file mode 100644
index ab901360..00000000
--- a/.gitlab-ci/debian-install.sh
+++ /dev/null
@@ -1,66 +0,0 @@
-#!/usr/bin/env bash
-set -o errexit
-set -o xtrace
-
-export DEBIAN_FRONTEND=noninteractive
-
-CROSS_ARCHITECTURES=(i386 armhf arm64 ppc64el)
-for arch in ${CROSS_ARCHITECTURES[@]}; do
-  dpkg --add-architecture $arch
-done
-
-apt-get install -y \
-  ca-certificates
-
-sed -i -e 's/http:\/\/deb/https:\/\/deb/g' /etc/apt/sources.list
-echo 'deb https://deb.debian.org/debian buster-backports main' >/etc/apt/sources.list.d/backports.list
-
-apt-get update
-
-# Use newer packages from backports by default
-cat >/etc/apt/preferences <<EOF
-Package: *
-Pin: release a=buster-backports
-Pin-Priority: 500
-EOF
-
-apt-get dist-upgrade -y
-
-apt-get install -y --no-remove \
-  build-essential \
-  docbook-xsl \
-  libatomic-ops-dev \
-  libcairo2-dev \
-  libcunit1-dev \
-  libpciaccess-dev \
-  meson \
-  ninja-build \
-  pkg-config \
-  python3 \
-  python3-pip \
-  python3-wheel \
-  python3-setuptools \
-  python3-docutils \
-  valgrind
-
-for arch in ${CROSS_ARCHITECTURES[@]}; do
-  cross_file=/cross_file-$arch.txt
-
-  # Cross-build libdrm deps
-  apt-get install -y --no-remove \
-    libcairo2-dev:$arch \
-    libpciaccess-dev:$arch \
-    crossbuild-essential-$arch
-
-  # Generate cross build files for Meson
-  /usr/share/meson/debcrossgen --arch $arch -o $cross_file
-
-  # Work around a bug in debcrossgen that should be fixed in the next release
-  if [ $arch = i386 ]; then
-    sed -i "s|cpu_family = 'i686'|cpu_family = 'x86'|g" $cross_file
-  fi
-done
-
-
-# Test that the oldest Meson version we claim to support is still supported
-pip3 install meson==0.46
diff --git a/Makefile.sources b/Makefile.sources
deleted file mode 100644
index 55290fe9..00000000
--- a/Makefile.sources
+++ /dev/null
@@ -1,45 +0,0 @@
-LIBDRM_FILES := \
-	xf86drm.c \
-	xf86drmHash.c \
-	xf86drmHash.h \
-	xf86drmRandom.c \
-	xf86drmRandom.h \
-	xf86drmSL.c \
-	xf86drmMode.c \
-	xf86atomic.h \
-	libdrm_macros.h \
-	libdrm_lists.h \
-	util_double_list.h \
-	util_math.h
-
-LIBDRM_H_FILES := \
-	libsync.h \
-	xf86drm.h \
-	xf86drmMode.h
-
-LIBDRM_INCLUDE_H_FILES := \
-	include/drm/drm.h \
-	include/drm/drm_fourcc.h \
-	include/drm/drm_mode.h \
-	include/drm/drm_sarea.h \
-	include/drm/i915_drm.h \
-	include/drm/mach64_drm.h \
-	include/drm/mga_drm.h \
-	include/drm/msm_drm.h \
-	include/drm/nouveau_drm.h \
-	include/drm/qxl_drm.h \
-	include/drm/r128_drm.h \
-	include/drm/radeon_drm.h \
-	include/drm/amdgpu_drm.h \
-	include/drm/savage_drm.h \
-	include/drm/sis_drm.h \
-	include/drm/tegra_drm.h \
-	include/drm/vc4_drm.h \
-	include/drm/via_drm.h \
-	include/drm/virtgpu_drm.h
-
-LIBDRM_INCLUDE_ANDROID_H_FILES := \
-	android/gralloc_handle.h
-
-LIBDRM_INCLUDE_VMWGFX_H_FILES := \
-	include/drm/vmwgfx_drm.h
diff --git a/amdgpu/Android.sources.bp b/amdgpu/Android.sources.bp
index be85283d..e2a2888b 100644
--- a/amdgpu/Android.sources.bp
+++ b/amdgpu/Android.sources.bp
@@ -3,13 +3,13 @@
 cc_defaults {
     name: "libdrm_amdgpu_sources",
     srcs: [
-	"amdgpu_asic_id.c",
+        "amdgpu_asic_id.c",
         "amdgpu_bo.c",
         "amdgpu_cs.c",
         "amdgpu_device.c",
         "amdgpu_gpu_info.c",
         "amdgpu_vamgr.c",
-	"amdgpu_vm.c",
+        "amdgpu_vm.c",
         "handle_table.c",
     ],
 }
diff --git a/amdgpu/Makefile.sources b/amdgpu/Makefile.sources
deleted file mode 100644
index d6df324a..00000000
--- a/amdgpu/Makefile.sources
+++ /dev/null
@@ -1,14 +0,0 @@
-LIBDRM_AMDGPU_FILES := \
-	amdgpu_asic_id.c \
-	amdgpu_bo.c \
-	amdgpu_cs.c \
-	amdgpu_device.c \
-	amdgpu_gpu_info.c \
-	amdgpu_internal.h \
-	amdgpu_vamgr.c \
-	amdgpu_vm.c \
-	handle_table.c \
-	handle_table.h
-
-LIBDRM_AMDGPU_H_FILES := \
-	amdgpu.h
diff --git a/amdgpu/amdgpu-symbols.txt b/amdgpu/amdgpu-symbols.txt
index d41d9c24..594480e3 100644
--- a/amdgpu/amdgpu-symbols.txt
+++ b/amdgpu/amdgpu-symbols.txt
@@ -56,6 +56,7 @@ amdgpu_cs_wait_semaphore
 amdgpu_device_deinitialize
 amdgpu_device_get_fd
 amdgpu_device_initialize
+amdgpu_device_initialize2
 amdgpu_find_bo_by_cpu_mapping
 amdgpu_get_marketing_name
 amdgpu_query_buffer_size_alignment
@@ -63,6 +64,7 @@ amdgpu_query_crtc_from_id
 amdgpu_query_firmware_version
 amdgpu_query_gds_info
 amdgpu_query_gpu_info
+amdgpu_query_gpuvm_fault_info
 amdgpu_query_heap_info
 amdgpu_query_hw_ip_count
 amdgpu_query_hw_ip_info
@@ -70,8 +72,13 @@ amdgpu_query_info
 amdgpu_query_sensor_info
 amdgpu_query_video_caps_info
 amdgpu_read_mm_registers
+amdgpu_va_manager_alloc
+amdgpu_va_manager_init
+amdgpu_va_manager_deinit
 amdgpu_va_range_alloc
+amdgpu_va_range_alloc2
 amdgpu_va_range_free
+amdgpu_va_get_start_addr
 amdgpu_va_range_query
 amdgpu_vm_reserve_vmid
 amdgpu_vm_unreserve_vmid
diff --git a/amdgpu/amdgpu.h b/amdgpu/amdgpu.h
index 5ef2524a..c9c1f12e 100644
--- a/amdgpu/amdgpu.h
+++ b/amdgpu/amdgpu.h
@@ -138,6 +138,12 @@ typedef struct amdgpu_bo_list *amdgpu_bo_list_handle;
  */
 typedef struct amdgpu_va *amdgpu_va_handle;
 
+/**
+ * Define handle dealing with VA allocation. An amdgpu_device
+ * owns one of these, but they can also be used without a device.
+ */
+typedef struct amdgpu_va_manager *amdgpu_va_manager_handle;
+
 /**
  * Define handle for semaphore
  */
@@ -527,6 +533,20 @@ int amdgpu_device_initialize(int fd,
 			     uint32_t *minor_version,
 			     amdgpu_device_handle *device_handle);
 
+/**
+ * Same as amdgpu_device_initialize() except when deduplicate_device
+ * is false *and* fd points to a device that was already initialized.
+ * In this case, amdgpu_device_initialize would return the same
+ * amdgpu_device_handle while here amdgpu_device_initialize2 would
+ * return a new handle.
+ * amdgpu_device_initialize() should be preferred in most situations;
+ * the only use-case where not-deduplicating devices make sense is
+ * when one wants to have isolated device handles in the same process.
+ */
+int amdgpu_device_initialize2(int fd, bool deduplicate_device,
+			      uint32_t *major_version,
+			      uint32_t *minor_version,
+			      amdgpu_device_handle *device_handle);
 /**
  *
  * When access to such library does not needed any more the special
@@ -1282,6 +1302,22 @@ int amdgpu_query_sensor_info(amdgpu_device_handle dev, unsigned sensor_type,
 int amdgpu_query_video_caps_info(amdgpu_device_handle dev, unsigned cap_type,
                                  unsigned size, void *value);
 
+/**
+ * Query information about VM faults
+ *
+ * The return sizeof(struct drm_amdgpu_info_gpuvm_fault)
+ *
+ * \param   dev         - \c [in] Device handle. See #amdgpu_device_initialize()
+ * \param   size        - \c [in] Size of the returned value.
+ * \param   value       - \c [out] Pointer to the return value.
+ *
+ * \return   0 on success\n
+ *          <0 - Negative POSIX Error code
+ *
+*/
+int amdgpu_query_gpuvm_fault_info(amdgpu_device_handle dev, unsigned size,
+				  void *value);
+
 /**
  * Read a set of consecutive memory-mapped registers.
  * Not all registers are allowed to be read by userspace.
@@ -1368,6 +1404,11 @@ int amdgpu_va_range_alloc(amdgpu_device_handle dev,
 */
 int amdgpu_va_range_free(amdgpu_va_handle va_range_handle);
 
+/**
+ * Return the starting address of the allocated virtual address range.
+ */
+uint64_t amdgpu_va_get_start_addr(amdgpu_va_handle va_handle);
+
 /**
 * Query virtual address range
 *
@@ -1389,6 +1430,37 @@ int amdgpu_va_range_query(amdgpu_device_handle dev,
 			  uint64_t *start,
 			  uint64_t *end);
 
+/**
+ * Allocate a amdgpu_va_manager object.
+ * The returned object has be initialized with the amdgpu_va_manager_init
+ * before use.
+ * On release, amdgpu_va_manager_deinit needs to be called, then the memory
+ * can be released using free().
+ */
+amdgpu_va_manager_handle amdgpu_va_manager_alloc(void);
+
+void amdgpu_va_manager_init(amdgpu_va_manager_handle va_mgr,
+			    uint64_t low_va_offset, uint64_t low_va_max,
+			    uint64_t high_va_offset, uint64_t high_va_max,
+			    uint32_t virtual_address_alignment);
+
+void amdgpu_va_manager_deinit(amdgpu_va_manager_handle va_mgr);
+
+/**
+ * Similar to #amdgpu_va_range_alloc() but allocates VA
+ * directly from an amdgpu_va_manager_handle instead of using
+ * the manager from an amdgpu_device.
+ */
+
+int amdgpu_va_range_alloc2(amdgpu_va_manager_handle va_mgr,
+			   enum amdgpu_gpu_va_range va_range_type,
+			   uint64_t size,
+			   uint64_t va_base_alignment,
+			   uint64_t va_base_required,
+			   uint64_t *va_base_allocated,
+			   amdgpu_va_handle *va_range_handle,
+			   uint64_t flags);
+
 /**
  *  VA mapping/unmapping for the buffer object
  *
diff --git a/amdgpu/amdgpu_bo.c b/amdgpu/amdgpu_bo.c
index 54b1fb90..672f000d 100644
--- a/amdgpu/amdgpu_bo.c
+++ b/amdgpu/amdgpu_bo.c
@@ -533,7 +533,7 @@ drm_public int amdgpu_find_bo_by_cpu_mapping(amdgpu_device_handle dev,
 					     amdgpu_bo_handle *buf_handle,
 					     uint64_t *offset_in_bo)
 {
-	struct amdgpu_bo *bo;
+	struct amdgpu_bo *bo = NULL;
 	uint32_t i;
 	int r = 0;
 
@@ -551,7 +551,7 @@ drm_public int amdgpu_find_bo_by_cpu_mapping(amdgpu_device_handle dev,
 		if (!bo || !bo->cpu_ptr || size > bo->alloc_size)
 			continue;
 		if (cpu >= bo->cpu_ptr &&
-		    cpu < (void*)((uintptr_t)bo->cpu_ptr + bo->alloc_size))
+		    cpu < (void*)((uintptr_t)bo->cpu_ptr + (size_t)bo->alloc_size))
 			break;
 	}
 
diff --git a/amdgpu/amdgpu_cs.c b/amdgpu/amdgpu_cs.c
index 638fd7d6..2db49675 100644
--- a/amdgpu/amdgpu_cs.c
+++ b/amdgpu/amdgpu_cs.c
@@ -56,10 +56,22 @@ drm_public int amdgpu_cs_ctx_create2(amdgpu_device_handle dev,
 	union drm_amdgpu_ctx args;
 	int i, j, k;
 	int r;
+	char *override_priority;
 
 	if (!dev || !context)
 		return -EINVAL;
 
+	override_priority = getenv("AMD_PRIORITY");
+	if (override_priority) {
+		/* The priority is a signed integer. The variable type is
+		 * wrong. If parsing fails, priority is unchanged.
+		 */
+		if (sscanf(override_priority, "%i", &priority) == 1) {
+			printf("amdgpu: context priority changed to %i\n",
+			       priority);
+		}
+	}
+
 	gpu_context = calloc(1, sizeof(struct amdgpu_context));
 	if (!gpu_context)
 		return -ENOMEM;
@@ -128,8 +140,8 @@ drm_public int amdgpu_cs_ctx_free(amdgpu_context_handle context)
 	for (i = 0; i < AMDGPU_HW_IP_NUM; i++) {
 		for (j = 0; j < AMDGPU_HW_IP_INSTANCE_MAX_COUNT; j++) {
 			for (k = 0; k < AMDGPU_CS_MAX_RINGS; k++) {
-				amdgpu_semaphore_handle sem;
-				LIST_FOR_EACH_ENTRY(sem, &context->sem_list[i][j][k], list) {
+				amdgpu_semaphore_handle sem, tmp;
+				LIST_FOR_EACH_ENTRY_SAFE(sem, tmp, &context->sem_list[i][j][k], list) {
 					list_del(&sem->list);
 					amdgpu_cs_reset_sem(sem);
 					amdgpu_cs_unreference_sem(sem);
@@ -586,24 +598,31 @@ drm_public int amdgpu_cs_signal_semaphore(amdgpu_context_handle ctx,
 			       uint32_t ring,
 			       amdgpu_semaphore_handle sem)
 {
+	int ret;
+
 	if (!ctx || !sem)
 		return -EINVAL;
 	if (ip_type >= AMDGPU_HW_IP_NUM)
 		return -EINVAL;
 	if (ring >= AMDGPU_CS_MAX_RINGS)
 		return -EINVAL;
-	/* sem has been signaled */
-	if (sem->signal_fence.context)
-		return -EINVAL;
+
 	pthread_mutex_lock(&ctx->sequence_mutex);
+	/* sem has been signaled */
+	if (sem->signal_fence.context) {
+		ret = -EINVAL;
+		goto unlock;
+	}
 	sem->signal_fence.context = ctx;
 	sem->signal_fence.ip_type = ip_type;
 	sem->signal_fence.ip_instance = ip_instance;
 	sem->signal_fence.ring = ring;
 	sem->signal_fence.fence = ctx->last_seq[ip_type][ip_instance][ring];
 	update_references(NULL, &sem->refcount);
+	ret = 0;
+unlock:
 	pthread_mutex_unlock(&ctx->sequence_mutex);
-	return 0;
+	return ret;
 }
 
 drm_public int amdgpu_cs_wait_semaphore(amdgpu_context_handle ctx,
diff --git a/amdgpu/amdgpu_device.c b/amdgpu/amdgpu_device.c
index 73fd27f6..34463b53 100644
--- a/amdgpu/amdgpu_device.c
+++ b/amdgpu/amdgpu_device.c
@@ -95,22 +95,26 @@ static int amdgpu_get_auth(int fd, int *auth)
 
 static void amdgpu_device_free_internal(amdgpu_device_handle dev)
 {
-	amdgpu_device_handle *node = &dev_list;
-
-	pthread_mutex_lock(&dev_mutex);
-	while (*node != dev && (*node)->next)
-		node = &(*node)->next;
-	*node = (*node)->next;
-	pthread_mutex_unlock(&dev_mutex);
+	/* Remove dev from dev_list, if it was added there. */
+	if (dev == dev_list) {
+		dev_list = dev->next;
+	} else {
+		for (amdgpu_device_handle node = dev_list; node; node = node->next) {
+			if (node->next == dev) {
+				node->next = dev->next;
+				break;
+			}
+		}
+	}
 
 	close(dev->fd);
 	if ((dev->flink_fd >= 0) && (dev->fd != dev->flink_fd))
 		close(dev->flink_fd);
 
-	amdgpu_vamgr_deinit(&dev->vamgr_32);
-	amdgpu_vamgr_deinit(&dev->vamgr);
-	amdgpu_vamgr_deinit(&dev->vamgr_high_32);
-	amdgpu_vamgr_deinit(&dev->vamgr_high);
+	amdgpu_vamgr_deinit(&dev->va_mgr.vamgr_32);
+	amdgpu_vamgr_deinit(&dev->va_mgr.vamgr_low);
+	amdgpu_vamgr_deinit(&dev->va_mgr.vamgr_high_32);
+	amdgpu_vamgr_deinit(&dev->va_mgr.vamgr_high);
 	handle_table_fini(&dev->bo_handles);
 	handle_table_fini(&dev->bo_flink_names);
 	pthread_mutex_destroy(&dev->bo_table_mutex);
@@ -140,22 +144,23 @@ static void amdgpu_device_reference(struct amdgpu_device **dst,
 	*dst = src;
 }
 
-drm_public int amdgpu_device_initialize(int fd,
-					uint32_t *major_version,
-					uint32_t *minor_version,
-					amdgpu_device_handle *device_handle)
+static int _amdgpu_device_initialize(int fd,
+				     uint32_t *major_version,
+				     uint32_t *minor_version,
+				     amdgpu_device_handle *device_handle,
+				     bool deduplicate_device)
 {
-	struct amdgpu_device *dev;
+	struct amdgpu_device *dev = NULL;
 	drmVersionPtr version;
 	int r;
 	int flag_auth = 0;
 	int flag_authexist=0;
 	uint32_t accel_working = 0;
-	uint64_t start, max;
 
 	*device_handle = NULL;
 
 	pthread_mutex_lock(&dev_mutex);
+
 	r = amdgpu_get_auth(fd, &flag_auth);
 	if (r) {
 		fprintf(stderr, "%s: amdgpu_get_auth (1) failed (%i)\n",
@@ -164,9 +169,10 @@ drm_public int amdgpu_device_initialize(int fd,
 		return r;
 	}
 
-	for (dev = dev_list; dev; dev = dev->next)
-		if (fd_compare(dev->fd, fd) == 0)
-			break;
+	if (deduplicate_device)
+		for (dev = dev_list; dev; dev = dev->next)
+			if (fd_compare(dev->fd, fd) == 0)
+				break;
 
 	if (dev) {
 		r = amdgpu_get_auth(dev->fd, &flag_authexist);
@@ -238,35 +244,22 @@ drm_public int amdgpu_device_initialize(int fd,
 		goto cleanup;
 	}
 
-	start = dev->dev_info.virtual_address_offset;
-	max = MIN2(dev->dev_info.virtual_address_max, 0x100000000ULL);
-	amdgpu_vamgr_init(&dev->vamgr_32, start, max,
-			  dev->dev_info.virtual_address_alignment);
-
-	start = max;
-	max = MAX2(dev->dev_info.virtual_address_max, 0x100000000ULL);
-	amdgpu_vamgr_init(&dev->vamgr, start, max,
-			  dev->dev_info.virtual_address_alignment);
-
-	start = dev->dev_info.high_va_offset;
-	max = MIN2(dev->dev_info.high_va_max, (start & ~0xffffffffULL) +
-		   0x100000000ULL);
-	amdgpu_vamgr_init(&dev->vamgr_high_32, start, max,
-			  dev->dev_info.virtual_address_alignment);
-
-	start = max;
-	max = MAX2(dev->dev_info.high_va_max, (start & ~0xffffffffULL) +
-		   0x100000000ULL);
-	amdgpu_vamgr_init(&dev->vamgr_high, start, max,
-			  dev->dev_info.virtual_address_alignment);
+	amdgpu_va_manager_init(&dev->va_mgr,
+			       dev->dev_info.virtual_address_offset,
+			       dev->dev_info.virtual_address_max,
+			       dev->dev_info.high_va_offset,
+			       dev->dev_info.high_va_max,
+			       dev->dev_info.virtual_address_alignment);
 
 	amdgpu_parse_asic_ids(dev);
 
 	*major_version = dev->major_version;
 	*minor_version = dev->minor_version;
 	*device_handle = dev;
-	dev->next = dev_list;
-	dev_list = dev;
+	if (deduplicate_device) {
+		dev->next = dev_list;
+		dev_list = dev;
+	}
 	pthread_mutex_unlock(&dev_mutex);
 
 	return 0;
@@ -279,9 +272,27 @@ cleanup:
 	return r;
 }
 
+drm_public int amdgpu_device_initialize(int fd,
+					uint32_t *major_version,
+					uint32_t *minor_version,
+					amdgpu_device_handle *device_handle)
+{
+	return _amdgpu_device_initialize(fd, major_version, minor_version, device_handle, true);
+}
+
+drm_public int amdgpu_device_initialize2(int fd, bool deduplicate_device,
+					 uint32_t *major_version,
+					 uint32_t *minor_version,
+					 amdgpu_device_handle *device_handle)
+{
+	return _amdgpu_device_initialize(fd, major_version, minor_version, device_handle, deduplicate_device);
+}
+
 drm_public int amdgpu_device_deinitialize(amdgpu_device_handle dev)
 {
+	pthread_mutex_lock(&dev_mutex);
 	amdgpu_device_reference(&dev, NULL);
+	pthread_mutex_unlock(&dev_mutex);
 	return 0;
 }
 
@@ -292,7 +303,10 @@ drm_public int amdgpu_device_get_fd(amdgpu_device_handle device_handle)
 
 drm_public const char *amdgpu_get_marketing_name(amdgpu_device_handle dev)
 {
-	return dev->marketing_name;
+	if (dev->marketing_name)
+		return dev->marketing_name;
+	else
+		return "AMD Radeon Graphics";
 }
 
 drm_public int amdgpu_query_sw_info(amdgpu_device_handle dev,
@@ -303,10 +317,10 @@ drm_public int amdgpu_query_sw_info(amdgpu_device_handle dev,
 
 	switch (info) {
 	case amdgpu_sw_info_address32_hi:
-		if (dev->vamgr_high_32.va_max)
-			*val32 = (dev->vamgr_high_32.va_max - 1) >> 32;
+		if (dev->va_mgr.vamgr_high_32.va_max)
+			*val32 = (dev->va_mgr.vamgr_high_32.va_max - 1) >> 32;
 		else
-			*val32 = (dev->vamgr_32.va_max - 1) >> 32;
+			*val32 = (dev->va_mgr.vamgr_32.va_max - 1) >> 32;
 		return 0;
 	}
 	return -EINVAL;
diff --git a/amdgpu/amdgpu_gpu_info.c b/amdgpu/amdgpu_gpu_info.c
index 9f8695ce..1a5143a6 100644
--- a/amdgpu/amdgpu_gpu_info.c
+++ b/amdgpu/amdgpu_gpu_info.c
@@ -346,3 +346,17 @@ drm_public int amdgpu_query_video_caps_info(amdgpu_device_handle dev, unsigned c
 	return drmCommandWrite(dev->fd, DRM_AMDGPU_INFO, &request,
 			       sizeof(struct drm_amdgpu_info));
 }
+
+drm_public int amdgpu_query_gpuvm_fault_info(amdgpu_device_handle dev,
+					     unsigned size, void *value)
+{
+	struct drm_amdgpu_info request;
+
+	memset(&request, 0, sizeof(request));
+	request.return_pointer = (uintptr_t)value;
+	request.return_size = size;
+	request.query = AMDGPU_INFO_GPUVM_FAULT;
+
+	return drmCommandWrite(dev->fd, DRM_AMDGPU_INFO, &request,
+			       sizeof(struct drm_amdgpu_info));
+}
diff --git a/amdgpu/amdgpu_internal.h b/amdgpu/amdgpu_internal.h
index 37a7c9d5..af85b849 100644
--- a/amdgpu/amdgpu_internal.h
+++ b/amdgpu/amdgpu_internal.h
@@ -57,13 +57,23 @@ struct amdgpu_bo_va_mgr {
 };
 
 struct amdgpu_va {
-	amdgpu_device_handle dev;
 	uint64_t address;
 	uint64_t size;
 	enum amdgpu_gpu_va_range range;
 	struct amdgpu_bo_va_mgr *vamgr;
 };
 
+struct amdgpu_va_manager {
+	/** The VA manager for the lower virtual address space */
+	struct amdgpu_bo_va_mgr vamgr_low;
+	/** The VA manager for the 32bit address space */
+	struct amdgpu_bo_va_mgr vamgr_32;
+	/** The VA manager for the high virtual address space */
+	struct amdgpu_bo_va_mgr vamgr_high;
+	/** The VA manager for the 32bit high address space */
+	struct amdgpu_bo_va_mgr vamgr_high_32;
+};
+
 struct amdgpu_device {
 	atomic_t refcount;
 	struct amdgpu_device *next;
@@ -81,14 +91,8 @@ struct amdgpu_device {
 	pthread_mutex_t bo_table_mutex;
 	struct drm_amdgpu_info_device dev_info;
 	struct amdgpu_gpu_info info;
-	/** The VA manager for the lower virtual address space */
-	struct amdgpu_bo_va_mgr vamgr;
-	/** The VA manager for the 32bit address space */
-	struct amdgpu_bo_va_mgr vamgr_32;
-	/** The VA manager for the high virtual address space */
-	struct amdgpu_bo_va_mgr vamgr_high;
-	/** The VA manager for the 32bit high address space */
-	struct amdgpu_bo_va_mgr vamgr_high_32;
+
+	struct amdgpu_va_manager va_mgr;
 };
 
 struct amdgpu_bo {
diff --git a/amdgpu/amdgpu_vamgr.c b/amdgpu/amdgpu_vamgr.c
index 077a9fc8..29944ec8 100644
--- a/amdgpu/amdgpu_vamgr.c
+++ b/amdgpu/amdgpu_vamgr.c
@@ -228,25 +228,40 @@ drm_public int amdgpu_va_range_alloc(amdgpu_device_handle dev,
 				     uint64_t *va_base_allocated,
 				     amdgpu_va_handle *va_range_handle,
 				     uint64_t flags)
+{
+	return amdgpu_va_range_alloc2(&dev->va_mgr, va_range_type, size,
+				      va_base_alignment, va_base_required,
+				      va_base_allocated, va_range_handle,
+				      flags);
+}
+
+drm_public int amdgpu_va_range_alloc2(amdgpu_va_manager_handle va_mgr,
+				      enum amdgpu_gpu_va_range va_range_type,
+				      uint64_t size,
+				      uint64_t va_base_alignment,
+				      uint64_t va_base_required,
+				      uint64_t *va_base_allocated,
+				      amdgpu_va_handle *va_range_handle,
+				      uint64_t flags)
 {
 	struct amdgpu_bo_va_mgr *vamgr;
 	bool search_from_top = !!(flags & AMDGPU_VA_RANGE_REPLAYABLE);
 	int ret;
 
 	/* Clear the flag when the high VA manager is not initialized */
-	if (flags & AMDGPU_VA_RANGE_HIGH && !dev->vamgr_high_32.va_max)
+	if (flags & AMDGPU_VA_RANGE_HIGH && !va_mgr->vamgr_high_32.va_max)
 		flags &= ~AMDGPU_VA_RANGE_HIGH;
 
 	if (flags & AMDGPU_VA_RANGE_HIGH) {
 		if (flags & AMDGPU_VA_RANGE_32_BIT)
-			vamgr = &dev->vamgr_high_32;
+			vamgr = &va_mgr->vamgr_high_32;
 		else
-			vamgr = &dev->vamgr_high;
+			vamgr = &va_mgr->vamgr_high;
 	} else {
 		if (flags & AMDGPU_VA_RANGE_32_BIT)
-			vamgr = &dev->vamgr_32;
+			vamgr = &va_mgr->vamgr_32;
 		else
-			vamgr = &dev->vamgr;
+			vamgr = &va_mgr->vamgr_low;
 	}
 
 	va_base_alignment = MAX2(va_base_alignment, vamgr->va_alignment);
@@ -259,9 +274,9 @@ drm_public int amdgpu_va_range_alloc(amdgpu_device_handle dev,
 	if (!(flags & AMDGPU_VA_RANGE_32_BIT) && ret) {
 		/* fallback to 32bit address */
 		if (flags & AMDGPU_VA_RANGE_HIGH)
-			vamgr = &dev->vamgr_high_32;
+			vamgr = &va_mgr->vamgr_high_32;
 		else
-			vamgr = &dev->vamgr_32;
+			vamgr = &va_mgr->vamgr_32;
 		ret = amdgpu_vamgr_find_va(vamgr, size,
 					   va_base_alignment, va_base_required,
 					   search_from_top, va_base_allocated);
@@ -274,7 +289,6 @@ drm_public int amdgpu_va_range_alloc(amdgpu_device_handle dev,
 			amdgpu_vamgr_free_va(vamgr, *va_base_allocated, size);
 			return -ENOMEM;
 		}
-		va->dev = dev;
 		va->address = *va_base_allocated;
 		va->size = size;
 		va->range = va_range_type;
@@ -296,3 +310,50 @@ drm_public int amdgpu_va_range_free(amdgpu_va_handle va_range_handle)
 	free(va_range_handle);
 	return 0;
 }
+
+drm_public uint64_t amdgpu_va_get_start_addr(amdgpu_va_handle va_handle)
+{
+   return va_handle->address;
+}
+
+drm_public amdgpu_va_manager_handle amdgpu_va_manager_alloc(void)
+{
+	amdgpu_va_manager_handle r = calloc(1, sizeof(struct amdgpu_va_manager));
+	return r;
+}
+
+drm_public void amdgpu_va_manager_init(struct amdgpu_va_manager *va_mgr,
+					uint64_t low_va_offset, uint64_t low_va_max,
+					uint64_t high_va_offset, uint64_t high_va_max,
+					uint32_t virtual_address_alignment)
+{
+	uint64_t start, max;
+
+	start = low_va_offset;
+	max = MIN2(low_va_max, 0x100000000ULL);
+	amdgpu_vamgr_init(&va_mgr->vamgr_32, start, max,
+			  virtual_address_alignment);
+
+	start = max;
+	max = MAX2(low_va_max, 0x100000000ULL);
+	amdgpu_vamgr_init(&va_mgr->vamgr_low, start, max,
+			  virtual_address_alignment);
+
+	start = high_va_offset;
+	max = MIN2(high_va_max, (start & ~0xffffffffULL) + 0x100000000ULL);
+	amdgpu_vamgr_init(&va_mgr->vamgr_high_32, start, max,
+			  virtual_address_alignment);
+
+	start = max;
+	max = MAX2(high_va_max, (start & ~0xffffffffULL) + 0x100000000ULL);
+	amdgpu_vamgr_init(&va_mgr->vamgr_high, start, max,
+			  virtual_address_alignment);
+}
+
+drm_public void amdgpu_va_manager_deinit(struct amdgpu_va_manager *va_mgr)
+{
+	amdgpu_vamgr_deinit(&va_mgr->vamgr_32);
+	amdgpu_vamgr_deinit(&va_mgr->vamgr_low);
+	amdgpu_vamgr_deinit(&va_mgr->vamgr_high_32);
+	amdgpu_vamgr_deinit(&va_mgr->vamgr_high);
+}
diff --git a/amdgpu/meson.build b/amdgpu/meson.build
index a1cca5a2..dd65fbb3 100644
--- a/amdgpu/meson.build
+++ b/amdgpu/meson.build
@@ -36,8 +36,8 @@ libdrm_amdgpu = library(
   ],
   include_directories : [inc_root, inc_drm],
   link_with : libdrm,
-  dependencies : [dep_pthread_stubs, dep_atomic_ops, dep_rt],
-  version : '1.0.0',
+  dependencies : [dep_threads, dep_atomic_ops, dep_rt],
+  version : '1.@0@.0'.format(patch_ver),
   install : true,
 )
 
@@ -65,6 +65,6 @@ test(
   args : [
     '--lib', libdrm_amdgpu,
     '--symbols-file', files('amdgpu-symbols.txt'),
-    '--nm', prog_nm.path(),
+    '--nm', prog_nm.full_path(),
   ],
 )
diff --git a/core-symbols.txt b/core-symbols.txt
index 31bbcf8f..766c342d 100644
--- a/core-symbols.txt
+++ b/core-symbols.txt
@@ -70,6 +70,7 @@ drmGetLibVersion
 drmGetLock
 drmGetMagic
 drmGetMap
+drmGetNodeTypeFromDevId
 drmGetNodeTypeFromFd
 drmGetPrimaryDeviceNameFromFd
 drmGetRenderDeviceNameFromFd
@@ -103,11 +104,15 @@ drmModeAtomicGetCursor
 drmModeAtomicMerge
 drmModeAtomicSetCursor
 drmModeAttachMode
+drmModeCloseFB
+drmModeConnectorGetPossibleCrtcs
 drmModeConnectorSetProperty
+drmModeCreateDumbBuffer
 drmModeCreateLease
 drmModeCreatePropertyBlob
 drmModeCrtcGetGamma
 drmModeCrtcSetGamma
+drmModeDestroyDumbBuffer
 drmModeDestroyPropertyBlob
 drmModeDetachMode
 drmModeDirtyFB
@@ -126,6 +131,7 @@ drmModeFreePropertyBlob
 drmModeFreeResources
 drmModeGetConnector
 drmModeGetConnectorCurrent
+drmModeGetConnectorTypeName
 drmModeGetCrtc
 drmModeGetEncoder
 drmModeGetFB
@@ -137,6 +143,7 @@ drmModeGetProperty
 drmModeGetPropertyBlob
 drmModeGetResources
 drmModeListLessees
+drmModeMapDumbBuffer
 drmModeMoveCursor
 drmModeObjectGetProperties
 drmModeObjectSetProperty
@@ -182,6 +189,7 @@ drmSLNext
 drmSwitchToContext
 drmSyncobjCreate
 drmSyncobjDestroy
+drmSyncobjEventfd
 drmSyncobjExportSyncFile
 drmSyncobjFDToHandle
 drmSyncobjHandleToFD
@@ -201,3 +209,4 @@ drmUpdateDrawableInfo
 drmWaitVBlank
 drmGetFormatModifierName
 drmGetFormatModifierVendor
+drmGetFormatName
diff --git a/data/amdgpu.ids b/data/amdgpu.ids
index 0040a38a..914d0e56 100644
--- a/data/amdgpu.ids
+++ b/data/amdgpu.ids
@@ -4,120 +4,237 @@
 # device_id,	revision_id,	product_name        <-- single tab after comma
 
 1.0.0
-15DD,	C3,	AMD Radeon Vega 3 Graphics
-15DD,	CB,	AMD Radeon Vega 3 Graphics
-15DD,	CE,	AMD Radeon Vega 3 Graphics
-15DD,	D8,	AMD Radeon Vega 3 Graphics
-15DD,	CC,	AMD Radeon Vega 6 Graphics
-15DD,	D9,	AMD Radeon Vega 6 Graphics
-15DD,	C2,	AMD Radeon Vega 8 Graphics
-15DD,	C4,	AMD Radeon Vega 8 Graphics
-15DD,	C8,	AMD Radeon Vega 8 Graphics
-15DD,	CA,	AMD Radeon Vega 8 Graphics
-15DD,	D1,	AMD Radeon Vega 8 Graphics
-15DD,	D5,	AMD Radeon Vega 8 Graphics
-15DD,	D7,	AMD Radeon Vega 8 Graphics
-15DD,	C3,	AMD Radeon Vega 10 Graphics
-15DD,	D0,	AMD Radeon Vega 10 Graphics
-15DD,	C1,	AMD Radeon Vega 11 Graphics
-15DD,	C6,	AMD Radeon Vega 11 Graphics
-15DD,	C9,	AMD Radeon Vega 11 Graphics
-15DD,	D3,	AMD Radeon Vega 11 Graphics
-15DD,	D6,	AMD Radeon Vega 11 Graphics
-15DD,	81,	AMD Ryzen Embedded V1807B with Radeon Vega Gfx
-15DD,	82,	AMD Ryzen Embedded V1756B with Radeon Vega Gfx
-15DD,	83,	AMD Ryzen Embedded V1605B with Radeon Vega Gfx
-15DD,	85,	AMD Ryzen Embedded V1202B with Radeon Vega Gfx
+1309,	00,	AMD Radeon R7 Graphics
+130A,	00,	AMD Radeon R6 Graphics
+130B,	00,	AMD Radeon R4 Graphics
+130C,	00,	AMD Radeon R7 Graphics
+130D,	00,	AMD Radeon R6 Graphics
+130E,	00,	AMD Radeon R5 Graphics
+130F,	00,	AMD Radeon R7 Graphics
+130F,	D4,	AMD Radeon R7 Graphics
+130F,	D5,	AMD Radeon R7 Graphics
+130F,	D6,	AMD Radeon R7 Graphics
+130F,	D7,	AMD Radeon R7 Graphics
+1313,	00,	AMD Radeon R7 Graphics
+1313,	D4,	AMD Radeon R7 Graphics
+1313,	D5,	AMD Radeon R7 Graphics
+1313,	D6,	AMD Radeon R7 Graphics
+1315,	00,	AMD Radeon R5 Graphics
+1315,	D4,	AMD Radeon R5 Graphics
+1315,	D5,	AMD Radeon R5 Graphics
+1315,	D6,	AMD Radeon R5 Graphics
+1315,	D7,	AMD Radeon R5 Graphics
+1316,	00,	AMD Radeon R5 Graphics
+1318,	00,	AMD Radeon R5 Graphics
+131B,	00,	AMD Radeon R4 Graphics
+131C,	00,	AMD Radeon R7 Graphics
+131D,	00,	AMD Radeon R6 Graphics
+1435,	AE,	AMD Custom GPU 0932
+1506,	C1,	AMD Radeon 610M
+1506,	C2,	AMD Radeon 610M
+1506,	C3,	AMD Radeon 610M
+1506,	C4,	AMD Radeon 610M
+15BF,	00,	AMD Radeon 780M
+15BF,	01,	AMD Radeon 760M
+15BF,	02,	AMD Radeon 780M
+15BF,	03,	AMD Radeon 760M
+15BF,	C1,	AMD Radeon 780M
+15BF,	C2,	AMD Radeon 780M
+15BF,	C3,	AMD Radeon 760M
+15BF,	C4,	AMD Radeon 780M
+15BF,	C5,	AMD Radeon 740M
+15BF,	C6,	AMD Radeon 780M
+15BF,	C7,	AMD Radeon 780M
+15BF,	C8,	AMD Radeon 760M
+15BF,	C9,	AMD Radeon 780M
+15BF,	CA,	AMD Radeon 740M
+15BF,	CB,	AMD Radeon 760M
+15BF,	CD,	AMD Radeon 760M
+15BF,	CF,	AMD Radeon 780M
+15BF,	D0,	AMD Radeon 780M
+15BF,	D1,	AMD Radeon 780M
+15BF,	D2,	AMD Radeon 760M
+15BF,	D3,	AMD Radeon 780M
+15BF,	D4,	AMD Radeon 780M
+15BF,	D5,	AMD Radeon 760M
+15BF,	D6,	AMD Radeon 760M
+15BF,	D7,	AMD Radeon 780M
+15BF,	D8,	AMD Radeon 740M
+15BF,	D9,	AMD Radeon 780M
+15BF,	DA,	AMD Radeon 780M
+15BF,	DB,	AMD Radeon 760M
+15BF,	DC,	AMD Radeon 780M
+15BF,	DD,	AMD Radeon 780M
+15BF,	DE,	AMD Radeon 740M
+15BF,	DF,	AMD Radeon 760M
+15BF,	F0,	AMD Radeon 760M
+15C8,	C1,	AMD Radeon 740M
+15C8,	C2,	AMD Radeon 740M
+15C8,	C3,	AMD Radeon 740M
+15C8,	C4,	AMD Radeon 740M
+15C8,	D1,	AMD Radeon 740M
+15C8,	D2,	AMD Radeon 740M
+15C8,	D3,	AMD Radeon 740M
+15C8,	D4,	AMD Radeon 740M
+15D8,	00,	AMD Radeon RX Vega 8 Graphics WS
+15D8,	91,	AMD Radeon Vega 3 Graphics
+15D8,	91,	AMD Ryzen Embedded R1606G with Radeon Vega Gfx
+15D8,	92,	AMD Radeon Vega 3 Graphics
+15D8,	92,	AMD Ryzen Embedded R1505G with Radeon Vega Gfx
 15D8,	93,	AMD Radeon Vega 1 Graphics
+15D8,	A1,	AMD Radeon Vega 10 Graphics
+15D8,	A2,	AMD Radeon Vega 8 Graphics
+15D8,	A3,	AMD Radeon Vega 6 Graphics
+15D8,	A4,	AMD Radeon Vega 3 Graphics
+15D8,	B1,	AMD Radeon Vega 10 Graphics
+15D8,	B2,	AMD Radeon Vega 8 Graphics
+15D8,	B3,	AMD Radeon Vega 6 Graphics
+15D8,	B4,	AMD Radeon Vega 3 Graphics
+15D8,	C1,	AMD Radeon Vega 10 Graphics
+15D8,	C2,	AMD Radeon Vega 8 Graphics
+15D8,	C3,	AMD Radeon Vega 6 Graphics
 15D8,	C4,	AMD Radeon Vega 3 Graphics
 15D8,	C5,	AMD Radeon Vega 3 Graphics
+15D8,	C8,	AMD Radeon Vega 11 Graphics
+15D8,	C9,	AMD Radeon Vega 8 Graphics
+15D8,	CA,	AMD Radeon Vega 11 Graphics
+15D8,	CB,	AMD Radeon Vega 8 Graphics
 15D8,	CC,	AMD Radeon Vega 3 Graphics
 15D8,	CE,	AMD Radeon Vega 3 Graphics
-15D8,	CF,	AMD Radeon Vega 3 Graphics
+15D8,	CF,	AMD Ryzen Embedded R1305G with Radeon Vega Gfx
+15D8,	D1,	AMD Radeon Vega 10 Graphics
+15D8,	D2,	AMD Radeon Vega 8 Graphics
+15D8,	D3,	AMD Radeon Vega 6 Graphics
 15D8,	D4,	AMD Radeon Vega 3 Graphics
+15D8,	D8,	AMD Radeon Vega 11 Graphics
+15D8,	D9,	AMD Radeon Vega 8 Graphics
+15D8,	DA,	AMD Radeon Vega 11 Graphics
+15D8,	DB,	AMD Radeon Vega 3 Graphics
+15D8,	DB,	AMD Radeon Vega 8 Graphics
 15D8,	DC,	AMD Radeon Vega 3 Graphics
 15D8,	DD,	AMD Radeon Vega 3 Graphics
 15D8,	DE,	AMD Radeon Vega 3 Graphics
 15D8,	DF,	AMD Radeon Vega 3 Graphics
 15D8,	E3,	AMD Radeon Vega 3 Graphics
-15D8,	E4,	AMD Radeon Vega 3 Graphics
-15D8,	A3,	AMD Radeon Vega 6 Graphics
-15D8,	B3,	AMD Radeon Vega 6 Graphics
-15D8,	C3,	AMD Radeon Vega 6 Graphics
-15D8,	D3,	AMD Radeon Vega 6 Graphics
-15D8,	A2,	AMD Radeon Vega 8 Graphics
-15D8,	B2,	AMD Radeon Vega 8 Graphics
-15D8,	C2,	AMD Radeon Vega 8 Graphics
-15D8,	C9,	AMD Radeon Vega 8 Graphics
-15D8,	CB,	AMD Radeon Vega 8 Graphics
-15D8,	D2,	AMD Radeon Vega 8 Graphics
-15D8,	D9,	AMD Radeon Vega 8 Graphics
-15D8,	DB,	AMD Radeon Vega 8 Graphics
-15D8,	A1,	AMD Radeon Vega 10 Graphics
-15D8,	B1,	AMD Radeon Vega 10 Graphics
-15D8,	C1,	AMD Radeon Vega 10 Graphics
-15D8,	D1,	AMD Radeon Vega 10 Graphics
-15D8,	C8,	AMD Radeon Vega 11 Graphics
-15D8,	CA,	AMD Radeon Vega 11 Graphics
-15D8,	D8,	AMD Radeon Vega 11 Graphics
-15D8,	DA,	AMD Radeon Vega 11 Graphics
-15D8,	91,	AMD Ryzen Embedded R1606G with Radeon Vega Gfx
-15D8,	92,	AMD Ryzen Embedded R1505G with Radeon Vega Gfx
-15D8,	CF,	AMD Ryzen Embedded R1305G with Radeon Vega Gfx
 15D8,	E4,	AMD Ryzen Embedded R1102G with Radeon Vega Gfx
+15DD,	81,	AMD Ryzen Embedded V1807B with Radeon Vega Gfx
+15DD,	82,	AMD Ryzen Embedded V1756B with Radeon Vega Gfx
+15DD,	83,	AMD Ryzen Embedded V1605B with Radeon Vega Gfx
+15DD,	84,	AMD Radeon Vega 6 Graphics
+15DD,	85,	AMD Ryzen Embedded V1202B with Radeon Vega Gfx
+15DD,	86,	AMD Radeon Vega 11 Graphics
+15DD,	88,	AMD Radeon Vega 8 Graphics
+15DD,	C1,	AMD Radeon Vega 11 Graphics
+15DD,	C2,	AMD Radeon Vega 8 Graphics
+15DD,	C3,	AMD Radeon Vega 3 / 10 Graphics
+15DD,	C4,	AMD Radeon Vega 8 Graphics
+15DD,	C5,	AMD Radeon Vega 3 Graphics
+15DD,	C6,	AMD Radeon Vega 11 Graphics
+15DD,	C8,	AMD Radeon Vega 8 Graphics
+15DD,	C9,	AMD Radeon Vega 11 Graphics
+15DD,	CA,	AMD Radeon Vega 8 Graphics
+15DD,	CB,	AMD Radeon Vega 3 Graphics
+15DD,	CC,	AMD Radeon Vega 6 Graphics
+15DD,	CE,	AMD Radeon Vega 3 Graphics
+15DD,	CF,	AMD Radeon Vega 3 Graphics
+15DD,	D0,	AMD Radeon Vega 10 Graphics
+15DD,	D1,	AMD Radeon Vega 8 Graphics
+15DD,	D3,	AMD Radeon Vega 11 Graphics
+15DD,	D5,	AMD Radeon Vega 8 Graphics
+15DD,	D6,	AMD Radeon Vega 11 Graphics
+15DD,	D7,	AMD Radeon Vega 8 Graphics
+15DD,	D8,	AMD Radeon Vega 3 Graphics
+15DD,	D9,	AMD Radeon Vega 6 Graphics
+15DD,	E1,	AMD Radeon Vega 3 Graphics
+15DD,	E2,	AMD Radeon Vega 3 Graphics
 163F,	AE,	AMD Custom GPU 0405
-6600,	0,	AMD Radeon HD 8600 / 8700M
+163F,	E1,	AMD Custom GPU 0405
+164E,	D8,	AMD Radeon 610M
+164E,	D9,	AMD Radeon 610M
+164E,	DA,	AMD Radeon 610M
+164E,	DB,	AMD Radeon 610M
+164E,	DC,	AMD Radeon 610M
+1681,	06,	AMD Radeon 680M
+1681,	07,	AMD Radeon 660M
+1681,	0A,	AMD Radeon 680M
+1681,	0B,	AMD Radeon 660M
+1681,	C7,	AMD Radeon 680M
+1681,	C8,	AMD Radeon 680M
+1681,	C9,	AMD Radeon 660M
+6600,	00,	AMD Radeon HD 8600 / 8700M
 6600,	81,	AMD Radeon R7 M370
-6601,	0,	AMD Radeon HD 8500M / 8700M
-6604,	0,	AMD Radeon R7 M265 Series
+6601,	00,	AMD Radeon HD 8500M / 8700M
+6604,	00,	AMD Radeon R7 M265 Series
 6604,	81,	AMD Radeon R7 M350
-6605,	0,	AMD Radeon R7 M260 Series
+6605,	00,	AMD Radeon R7 M260 Series
 6605,	81,	AMD Radeon R7 M340
-6606,	0,	AMD Radeon HD 8790M
-6607,	0,	AMD Radeon HD 8530M
-6608,	0,	AMD FirePro W2100
-6610,	0,	AMD Radeon HD 8600 Series
+6606,	00,	AMD Radeon HD 8790M
+6607,	00,	AMD Radeon R5 M240
+6608,	00,	AMD FirePro W2100
+6610,	00,	AMD Radeon R7 200 Series
 6610,	81,	AMD Radeon R7 350
 6610,	83,	AMD Radeon R5 340
-6611,	0,	AMD Radeon HD 8500 Series
-6613,	0,	AMD Radeon HD 8500 series
+6610,	87,	AMD Radeon R7 200 Series
+6611,	00,	AMD Radeon R7 200 Series
+6611,	87,	AMD Radeon R7 200 Series
+6613,	00,	AMD Radeon R7 200 Series
+6617,	00,	AMD Radeon R7 240 Series
+6617,	87,	AMD Radeon R7 200 Series
 6617,	C7,	AMD Radeon R7 240 Series
-6640,	0,	AMD Radeon HD 8950
+6640,	00,	AMD Radeon HD 8950
 6640,	80,	AMD Radeon R9 M380
-6646,	0,	AMD Radeon R9 M280X
+6646,	00,	AMD Radeon R9 M280X
+6646,	80,	AMD Radeon R9 M385
 6646,	80,	AMD Radeon R9 M470X
-6647,	0,	AMD Radeon R9 M270X
+6647,	00,	AMD Radeon R9 M200X Series
 6647,	80,	AMD Radeon R9 M380
-6649,	0,	AMD FirePro W5100
-6658,	0,	AMD Radeon R7 200 Series
-665C,	0,	AMD Radeon HD 7700 Series
-665D,	0,	AMD Radeon R7 200 Series
-665F,	81,	AMD Radeon R7 300 Series
-6660,	0,	AMD Radeon HD 8600M Series
+6649,	00,	AMD FirePro W5100
+6658,	00,	AMD Radeon R7 200 Series
+665C,	00,	AMD Radeon HD 7700 Series
+665D,	00,	AMD Radeon R7 200 Series
+665F,	81,	AMD Radeon R7 360 Series
+6660,	00,	AMD Radeon HD 8600M Series
 6660,	81,	AMD Radeon R5 M335
 6660,	83,	AMD Radeon R5 M330
-6663,	0,	AMD Radeon HD 8500M Series
+6663,	00,	AMD Radeon HD 8500M Series
 6663,	83,	AMD Radeon R5 M320
-6664,	0,	AMD Radeon R5 M200 Series
-6665,	0,	AMD Radeon R5 M200 Series
+6664,	00,	AMD Radeon R5 M200 Series
+6665,	00,	AMD Radeon R5 M230 Series
 6665,	83,	AMD Radeon R5 M320
-6667,	0,	AMD Radeon R5 M200 Series
-666F,	0,	AMD Radeon HD 8500M
+6665,	C3,	AMD Radeon R5 M435
+6666,	00,	AMD Radeon R5 M200 Series
+6667,	00,	AMD Radeon R5 M200 Series
+666F,	00,	AMD Radeon HD 8500M
+66A1,	02,	AMD Instinct MI60 / MI50
 66A1,	06,	AMD Radeon Pro VII
 66AF,	C1,	AMD Radeon VII
-6780,	0,	ATI FirePro V (FireGL V) Graphics Adapter
-678A,	0,	ATI FirePro V (FireGL V) Graphics Adapter
-6798,	0,	AMD Radeon HD 7900 Series
-679A,	0,	AMD Radeon HD 7900 Series
-679B,	0,	AMD Radeon HD 7900 Series
-679E,	0,	AMD Radeon HD 7800 Series
-67A0,	0,	AMD Radeon FirePro W9100
-67A1,	0,	AMD Radeon FirePro W8100
-67B0,	0,	AMD Radeon R9 200 Series
+6780,	00,	AMD FirePro W9000
+6784,	00,	ATI FirePro V (FireGL V) Graphics Adapter
+6788,	00,	ATI FirePro V (FireGL V) Graphics Adapter
+678A,	00,	AMD FirePro W8000
+6798,	00,	AMD Radeon R9 200 / HD 7900 Series
+6799,	00,	AMD Radeon HD 7900 Series
+679A,	00,	AMD Radeon HD 7900 Series
+679B,	00,	AMD Radeon HD 7900 Series
+679E,	00,	AMD Radeon HD 7800 Series
+67A0,	00,	AMD Radeon FirePro W9100
+67A1,	00,	AMD Radeon FirePro W8100
+67B0,	00,	AMD Radeon R9 200 Series
 67B0,	80,	AMD Radeon R9 390 Series
-67B1,	0,	AMD Radeon R9 200 Series
+67B1,	00,	AMD Radeon R9 200 Series
 67B1,	80,	AMD Radeon R9 390 Series
-67B9,	0,	AMD Radeon R9 200 Series
+67B9,	00,	AMD Radeon R9 200 Series
+67C0,	00,	AMD Radeon Pro WX 7100 Graphics
+67C0,	80,	AMD Radeon E9550
+67C2,	01,	AMD Radeon Pro V7350x2
+67C2,	02,	AMD Radeon Pro V7300X
+67C4,	00,	AMD Radeon Pro WX 7100 Graphics
+67C4,	80,	AMD Radeon E9560 / E9565 Graphics
+67C7,	00,	AMD Radeon Pro WX 5100 Graphics
+67C7,	80,	AMD Radeon E9390 Graphics
+67D0,	01,	AMD Radeon Pro V7350x2
+67D0,	02,	AMD Radeon Pro V7300X
+67DF,	C0,	AMD Radeon Pro 580X
 67DF,	C1,	AMD Radeon RX 580 Series
 67DF,	C2,	AMD Radeon RX 570 Series
 67DF,	C3,	AMD Radeon RX 580 Series
@@ -131,17 +248,10 @@
 67DF,	E1,	AMD Radeon RX 590 Series
 67DF,	E3,	AMD Radeon RX Series
 67DF,	E7,	AMD Radeon RX 580 Series
+67DF,	EB,	AMD Radeon Pro 580X
 67DF,	EF,	AMD Radeon RX 570 Series
 67DF,	F7,	AMD Radeon RX P30PH
-67C2,	01,	AMD Radeon Pro V7350x2
-67C2,	02,	AMD Radeon Pro V7300X
-67C4,	00,	AMD Radeon Pro WX 7100 Graphics
-67C4,	80,	AMD Radeon E9560 / E9565 Graphics
-67C7,	00,	AMD Radeon Pro WX 5100 Graphics
-67C7,	80,	AMD Radeon E9390 Graphics
-67C0,	00,	AMD Radeon Pro WX 7100 Graphics
-67D0,	01,	AMD Radeon Pro V7350x2
-67D0,	02,	AMD Radeon Pro V7300X
+67DF,	FF,	AMD Radeon RX 470 Series
 67E0,	00,	AMD Radeon Pro WX Series
 67E3,	00,	AMD Radeon Pro WX 4100
 67E8,	00,	AMD Radeon Pro WX Series
@@ -150,52 +260,60 @@
 67EB,	00,	AMD Radeon Pro V5300X
 67EF,	C0,	AMD Radeon RX Graphics
 67EF,	C1,	AMD Radeon RX 460 Graphics
+67EF,	C2,	AMD Radeon Pro Series
 67EF,	C3,	AMD Radeon RX Series
 67EF,	C5,	AMD Radeon RX 460 Graphics
 67EF,	C7,	AMD Radeon RX Graphics
 67EF,	CF,	AMD Radeon RX 460 Graphics
-67EF,	E2,	AMD Radeon RX 560X
 67EF,	E0,	AMD Radeon RX 560 Series
 67EF,	E1,	AMD Radeon RX Series
+67EF,	E2,	AMD Radeon RX 560X
 67EF,	E3,	AMD Radeon RX Series
 67EF,	E5,	AMD Radeon RX 560 Series
-67EF,	EF,	AMD Radeon RX Graphics
+67EF,	E7,	AMD Radeon RX 560 Series
+67EF,	EF,	AMD Radeon 550 Series
 67EF,	FF,	AMD Radeon RX 460 Graphics
-67FF,	C0,	AMD Radeon RX Graphics
-67FF,	C1,	AMD Radeon RX Graphics
+67FF,	C0,	AMD Radeon Pro 465
+67FF,	C1,	AMD Radeon RX 560 Series
 67FF,	CF,	AMD Radeon RX 560 Series
 67FF,	EF,	AMD Radeon RX 560 Series
 67FF,	FF,	AMD Radeon RX 550 Series
-6800,	0,	AMD Radeon HD 7970M
-6801,	0,	AMD Radeon HD 8970M
-6808,	0,	ATI FirePro V(FireGL V) Graphics Adapter
-6809,	0,	ATI FirePro V(FireGL V) Graphics Adapter
-6810,	0,	AMD Radeon HD 8800 Series
-6810,	81,	AMD Radeon R7 370 Series
-6811,	0,	AMD Radeon HD 8800 Series
-6811,	81,	AMD Radeon R7 300 Series
-6818,	0,	AMD Radeon HD 7800 Series
-6819,	0,	AMD Radeon HD 7800 Series
-6820,	0,	AMD Radeon HD 8800M Series
+6800,	00,	AMD Radeon HD 7970M
+6801,	00,	AMD Radeon HD 8970M
+6806,	00,	AMD Radeon R9 M290X
+6808,	00,	AMD FirePro W7000
+6808,	00,	ATI FirePro V (FireGL V) Graphics Adapter
+6809,	00,	ATI FirePro W5000
+6810,	00,	AMD Radeon R9 200 Series
+6810,	81,	AMD Radeon R9 370 Series
+6811,	00,	AMD Radeon R9 200 Series
+6811,	81,	AMD Radeon R7 370 Series
+6818,	00,	AMD Radeon HD 7800 Series
+6819,	00,	AMD Radeon HD 7800 Series
+6820,	00,	AMD Radeon R9 M275X
 6820,	81,	AMD Radeon R9 M375
 6820,	83,	AMD Radeon R9 M375X
-6821,	0,	AMD Radeon HD 8800M Series
-6821,	87,	AMD Radeon R7 M380
+6821,	00,	AMD Radeon R9 M200X Series
 6821,	83,	AMD Radeon R9 M370X
-6822,	0,	AMD Radeon E8860
-6823,	0,	AMD Radeon HD 8800M Series
-6825,	0,	AMD Radeon HD 7800M Series
-6827,	0,	AMD Radeon HD 7800M Series
-6828,	0,	ATI FirePro V(FireGL V) Graphics Adapter
-682B,	0,	AMD Radeon HD 8800M Series
+6821,	87,	AMD Radeon R7 M380
+6822,	00,	AMD Radeon E8860
+6823,	00,	AMD Radeon R9 M200X Series
+6825,	00,	AMD Radeon HD 7800M Series
+6826,	00,	AMD Radeon HD 7700M Series
+6827,	00,	AMD Radeon HD 7800M Series
+6828,	00,	AMD FirePro W600
+682B,	00,	AMD Radeon HD 8800M Series
 682B,	87,	AMD Radeon R9 M360
-682C,	0,	AMD FirePro W4100
-682D,	0,	AMD Radeon HD 7700M Series
-682F,	0,	AMD Radeon HD 7700M Series
-6835,	0,	AMD Radeon R7 Series / HD 9000 Series
-6837,	0,	AMD Radeon HD 7700 Series
-683D,	0,	AMD Radeon HD 7700 Series
-683F,	0,	AMD Radeon HD 7700 Series
+682C,	00,	AMD FirePro W4100
+682D,	00,	AMD Radeon HD 7700M Series
+682F,	00,	AMD Radeon HD 7700M Series
+6830,	00,	AMD Radeon 7800M Series
+6831,	00,	AMD Radeon 7700M Series
+6835,	00,	AMD Radeon R7 Series / HD 9000 Series
+6837,	00,	AMD Radeon HD 7700 Series
+683D,	00,	AMD Radeon HD 7700 Series
+683F,	00,	AMD Radeon HD 7700 Series
+684C,	00,	ATI FirePro V (FireGL V) Graphics Adapter
 6860,	00,	AMD Radeon Instinct MI25
 6860,	01,	AMD Radeon Instinct MI25
 6860,	02,	AMD Radeon Instinct MI25
@@ -207,6 +325,7 @@
 6863,	00,	AMD Radeon Vega Frontier Edition
 6864,	03,	AMD Radeon Pro V340
 6864,	04,	AMD Radeon Instinct MI25x2
+6864,	05,	AMD Radeon Pro V340
 6868,	00,	AMD Radeon Pro WX 8200
 686C,	00,	AMD Radeon Instinct MI25 MxGPU
 686C,	01,	AMD Radeon Instinct MI25 MxGPU
@@ -215,35 +334,47 @@
 686C,	04,	AMD Radeon Instinct MI25x2 MxGPU
 686C,	05,	AMD Radeon Pro V340L MxGPU
 686C,	06,	AMD Radeon Instinct MI25 MxGPU
+687F,	01,	AMD Radeon RX Vega
 687F,	C0,	AMD Radeon RX Vega
 687F,	C1,	AMD Radeon RX Vega
 687F,	C3,	AMD Radeon RX Vega
-6900,	0,	AMD Radeon R7 M260
+687F,	C7,	AMD Radeon RX Vega
+6900,	00,	AMD Radeon R7 M260
 6900,	81,	AMD Radeon R7 M360
 6900,	83,	AMD Radeon R7 M340
-6901,	0,	AMD Radeon R5 M255
-6907,	0,	AMD Radeon R5 M255
+6900,	C1,	AMD Radeon R5 M465 Series
+6900,	C3,	AMD Radeon R5 M445 Series
+6900,	D1,	AMD Radeon 530 Series
+6900,	D3,	AMD Radeon 530 Series
+6901,	00,	AMD Radeon R5 M255
+6902,	00,	AMD Radeon Series
+6907,	00,	AMD Radeon R5 M255
 6907,	87,	AMD Radeon R5 M315
-6920,	0,	AMD Radeon R9 M395X
-6920,	1,	AMD Radeon R9 M390X
-6921,	0,	AMD Radeon R9 M295X
-6929,	0,	AMD FirePro S7150
-692B,	0,	AMD FirePro W7100
-6938,	0,	AMD Radeon R9 200 Series
+6920,	00,	AMD Radeon R9 M395X
+6920,	01,	AMD Radeon R9 M390X
+6921,	00,	AMD Radeon R9 M390X
+6929,	00,	AMD FirePro S7150
+6929,	01,	AMD FirePro S7100X
+692B,	00,	AMD FirePro W7100
+6938,	00,	AMD Radeon R9 200 Series
 6938,	F0,	AMD Radeon R9 200 Series
 6938,	F1,	AMD Radeon R9 380 Series
+6939,	00,	AMD Radeon R9 200 Series
 6939,	F0,	AMD Radeon R9 200 Series
-6939,	0,	AMD Radeon R9 200 Series
 6939,	F1,	AMD Radeon R9 380 Series
+694C,	C0,	AMD Radeon RX Vega M GH Graphics
+694E,	C0,	AMD Radeon RX Vega M GL Graphics
 6980,	00,	AMD Radeon Pro WX 3100
 6981,	00,	AMD Radeon Pro WX 3200 Series
 6981,	01,	AMD Radeon Pro WX 3200 Series
 6981,	10,	AMD Radeon Pro WX 3200 Series
 6985,	00,	AMD Radeon Pro WX 3100
+6986,	00,	AMD Radeon Pro WX 2100
 6987,	80,	AMD Embedded Radeon E9171
 6987,	C0,	AMD Radeon 550X Series
 6987,	C1,	AMD Radeon RX 640
 6987,	C3,	AMD Radeon 540X Series
+6987,	C7,	AMD Radeon 540
 6995,	00,	AMD Radeon Pro WX 2100
 6997,	00,	AMD Radeon Pro WX 2100
 699F,	81,	AMD Embedded Radeon E9170 Series
@@ -251,11 +382,14 @@
 699F,	C1,	AMD Radeon 540 Series
 699F,	C3,	AMD Radeon 500 Series
 699F,	C7,	AMD Radeon RX 550 / 550 Series
+699F,	C9,	AMD Radeon 540
+6FDF,	E7,	AMD Radeon RX 590 GME
+6FDF,	EF,	AMD Radeon RX 580 2048SP
 7300,	C1,	AMD FirePro S9300 x2
 7300,	C8,	AMD Radeon R9 Fury Series
 7300,	C9,	AMD Radeon Pro Duo
-7300,	CB,	AMD Radeon R9 Fury Series
 7300,	CA,	AMD Radeon R9 Fury Series
+7300,	CB,	AMD Radeon R9 Fury Series
 7312,	00,	AMD Radeon Pro W5700
 731E,	C6,	AMD Radeon RX 5700XTB
 731E,	C7,	AMD Radeon RX 5700B
@@ -268,33 +402,185 @@
 731F,	CA,	AMD Radeon RX 5600 XT
 731F,	CB,	AMD Radeon RX 5600 OEM
 7340,	C1,	AMD Radeon RX 5500M
+7340,	C3,	AMD Radeon RX 5300M
 7340,	C5,	AMD Radeon RX 5500 XT
 7340,	C7,	AMD Radeon RX 5500
 7340,	C9,	AMD Radeon RX 5500XTB
 7340,	CF,	AMD Radeon RX 5300
 7341,	00,	AMD Radeon Pro W5500
 7347,	00,	AMD Radeon Pro W5500M
+7360,	41,	AMD Radeon Pro 5600M
+7360,	C3,	AMD Radeon Pro V520
+7362,	C1,	AMD Radeon Pro V540
+7362,	C3,	AMD Radeon Pro V520
+738C,	01,	AMD Instinct MI100
+73A1,	00,	AMD Radeon Pro V620
 73A3,	00,	AMD Radeon Pro W6800
+73A5,	C0,	AMD Radeon RX 6950 XT
+73AE,	00,	AMD Radeon Pro V620
 73AF,	C0,	AMD Radeon RX 6900 XT
 73BF,	C0,	AMD Radeon RX 6900 XT
 73BF,	C1,	AMD Radeon RX 6800 XT
 73BF,	C3,	AMD Radeon RX 6800
+73DF,	C0,	AMD Radeon RX 6750 XT
 73DF,	C1,	AMD Radeon RX 6700 XT
+73DF,	C2,	AMD Radeon RX 6800M
 73DF,	C3,	AMD Radeon RX 6800M
 73DF,	C5,	AMD Radeon RX 6700 XT
 73DF,	CF,	AMD Radeon RX 6700M
+73DF,	D5,	AMD Radeon RX 6750 GRE 12GB
+73DF,	D7,	AMD TDC-235
+73DF,	DF,	AMD Radeon RX 6700
+73DF,	E5,	AMD Radeon RX 6750 GRE 12GB
+73DF,	FF,	AMD Radeon RX 6700
+73E0,	00,	AMD Radeon RX 6600M
 73E1,	00,	AMD Radeon Pro W6600M
 73E3,	00,	AMD Radeon Pro W6600
+73EF,	C0,	AMD Radeon RX 6800S
+73EF,	C1,	AMD Radeon RX 6650 XT
+73EF,	C2,	AMD Radeon RX 6700S
+73EF,	C3,	AMD Radeon RX 6650M
+73EF,	C4,	AMD Radeon RX 6650M XT
 73FF,	C1,	AMD Radeon RX 6600 XT
 73FF,	C3,	AMD Radeon RX 6600M
+73FF,	C7,	AMD Radeon RX 6600
+73FF,	CB,	AMD Radeon RX 6600S
+73FF,	CF,	AMD Radeon RX 6600 LE
+73FF,	DF,	AMD Radeon RX 6750 GRE 10GB
+7408,	00,	AMD Instinct MI250X
+740C,	01,	AMD Instinct MI250X / MI250
+740F,	02,	AMD Instinct MI210
+7421,	00,	AMD Radeon Pro W6500M
+7422,	00,	AMD Radeon Pro W6400
+7423,	00,	AMD Radeon Pro W6300M
+7423,	01,	AMD Radeon Pro W6300
+7424,	00,	AMD Radeon RX 6300
+743F,	C1,	AMD Radeon RX 6500 XT
+743F,	C3,	AMD Radeon RX 6500
+743F,	C3,	AMD Radeon RX 6500M
+743F,	C7,	AMD Radeon RX 6400
+743F,	C8,	AMD Radeon RX 6500M
+743F,	CC,	AMD Radeon 6550S
+743F,	CE,	AMD Radeon RX 6450M
+743F,	CF,	AMD Radeon RX 6300M
+743F,	D3,	AMD Radeon RX 6550M
+743F,	D7,	AMD Radeon RX 6400
+7448,	00,	AMD Radeon Pro W7900
+744A,	00,	AMD Radeon Pro W7900 Dual Slot
+744C,	C8,	AMD Radeon RX 7900 XTX
+744C,	CC,	AMD Radeon RX 7900 XT
+744C,	CE,	AMD Radeon RX 7900 GRE
+744C,	CF,	AMD Radeon RX 7900M
+745E,	CC,	AMD Radeon Pro W7800
+7460,	00,	AMD Radeon Pro V710
+7461,	00,	AMD Radeon Pro V710
+7470,	00,	AMD Radeon Pro W7700
+747E,	C8,	AMD Radeon RX 7800 XT
+747E,	FF,	AMD Radeon RX 7700 XT
+7480,	00,	AMD Radeon Pro W7600
+7480,	C0,	AMD Radeon RX 7600 XT
+7480,	C1,	AMD Radeon RX 7700S
+7480,	C3,	AMD Radeon RX 7600S
+7480,	C7,	AMD Radeon RX 7600M XT
+7480,	CF,	AMD Radeon RX 7600
+7483,	CF,	AMD Radeon RX 7600M
+7489,	00,	AMD Radeon Pro W7500
+74A0,	00,	AMD Instinct MI300A
+74A1,	00,	AMD Instinct MI300X
+74B5,	00,	AMD Instinct MI300X VF
+9830,	00,	AMD Radeon HD 8400 / R3 Series
+9831,	00,	AMD Radeon HD 8400E
+9832,	00,	AMD Radeon HD 8330
+9833,	00,	AMD Radeon HD 8330E
+9834,	00,	AMD Radeon HD 8210
+9835,	00,	AMD Radeon HD 8210E
+9836,	00,	AMD Radeon HD 8200 / R3 Series
+9837,	00,	AMD Radeon HD 8280E
+9838,	00,	AMD Radeon HD 8200 / R3 series
+9839,	00,	AMD Radeon HD 8180
+983D,	00,	AMD Radeon HD 8250
+9850,	00,	AMD Radeon R3 Graphics
+9850,	03,	AMD Radeon R3 Graphics
+9850,	40,	AMD Radeon R2 Graphics
+9850,	45,	AMD Radeon R3 Graphics
+9851,	00,	AMD Radeon R4 Graphics
+9851,	01,	AMD Radeon R5E Graphics
+9851,	05,	AMD Radeon R5 Graphics
+9851,	06,	AMD Radeon R5E Graphics
+9851,	40,	AMD Radeon R4 Graphics
+9851,	45,	AMD Radeon R5 Graphics
+9852,	00,	AMD Radeon R2 Graphics
+9852,	40,	AMD Radeon E1 Graphics
+9853,	00,	AMD Radeon R2 Graphics
+9853,	01,	AMD Radeon R4E Graphics
+9853,	03,	AMD Radeon R2 Graphics
+9853,	05,	AMD Radeon R1E Graphics
+9853,	06,	AMD Radeon R1E Graphics
+9853,	07,	AMD Radeon R1E Graphics
+9853,	08,	AMD Radeon R1E Graphics
+9853,	40,	AMD Radeon R2 Graphics
+9854,	00,	AMD Radeon R3 Graphics
+9854,	01,	AMD Radeon R3E Graphics
+9854,	02,	AMD Radeon R3 Graphics
+9854,	05,	AMD Radeon R2 Graphics
+9854,	06,	AMD Radeon R4 Graphics
+9854,	07,	AMD Radeon R3 Graphics
+9855,	02,	AMD Radeon R6 Graphics
+9855,	05,	AMD Radeon R4 Graphics
+9856,	00,	AMD Radeon R2 Graphics
+9856,	01,	AMD Radeon R2E Graphics
+9856,	02,	AMD Radeon R2 Graphics
+9856,	05,	AMD Radeon R1E Graphics
+9856,	06,	AMD Radeon R2 Graphics
+9856,	07,	AMD Radeon R1E Graphics
+9856,	08,	AMD Radeon R1E Graphics
+9856,	13,	AMD Radeon R1E Graphics
+9874,	81,	AMD Radeon R6 Graphics
+9874,	84,	AMD Radeon R7 Graphics
+9874,	85,	AMD Radeon R6 Graphics
+9874,	87,	AMD Radeon R5 Graphics
+9874,	88,	AMD Radeon R7E Graphics
+9874,	89,	AMD Radeon R6E Graphics
 9874,	C4,	AMD Radeon R7 Graphics
 9874,	C5,	AMD Radeon R6 Graphics
 9874,	C6,	AMD Radeon R6 Graphics
 9874,	C7,	AMD Radeon R5 Graphics
 9874,	C8,	AMD Radeon R7 Graphics
-9874,	81,	AMD Radeon R6 Graphics
-9874,	87,	AMD Radeon R5 Graphics
-9874,	85,	AMD Radeon R6 Graphics
-9874,	84,	AMD Radeon R7 Graphics
-6FDF,	E7,	AMD Radeon RX 590 GME
-6FDF,	EF,	AMD Radeon RX 580 2048SP
+9874,	C9,	AMD Radeon R7 Graphics
+9874,	CA,	AMD Radeon R5 Graphics
+9874,	CB,	AMD Radeon R5 Graphics
+9874,	CC,	AMD Radeon R7 Graphics
+9874,	CD,	AMD Radeon R7 Graphics
+9874,	CE,	AMD Radeon R5 Graphics
+9874,	E1,	AMD Radeon R7 Graphics
+9874,	E2,	AMD Radeon R7 Graphics
+9874,	E3,	AMD Radeon R7 Graphics
+9874,	E4,	AMD Radeon R7 Graphics
+9874,	E5,	AMD Radeon R5 Graphics
+9874,	E6,	AMD Radeon R5 Graphics
+98E4,	80,	AMD Radeon R5E Graphics
+98E4,	81,	AMD Radeon R4E Graphics
+98E4,	83,	AMD Radeon R2E Graphics
+98E4,	84,	AMD Radeon R2E Graphics
+98E4,	86,	AMD Radeon R1E Graphics
+98E4,	C0,	AMD Radeon R4 Graphics
+98E4,	C1,	AMD Radeon R5 Graphics
+98E4,	C2,	AMD Radeon R4 Graphics
+98E4,	C4,	AMD Radeon R5 Graphics
+98E4,	C6,	AMD Radeon R5 Graphics
+98E4,	C8,	AMD Radeon R4 Graphics
+98E4,	C9,	AMD Radeon R4 Graphics
+98E4,	CA,	AMD Radeon R5 Graphics
+98E4,	D0,	AMD Radeon R2 Graphics
+98E4,	D1,	AMD Radeon R2 Graphics
+98E4,	D2,	AMD Radeon R2 Graphics
+98E4,	D4,	AMD Radeon R2 Graphics
+98E4,	D9,	AMD Radeon R5 Graphics
+98E4,	DA,	AMD Radeon R5 Graphics
+98E4,	DB,	AMD Radeon R3 Graphics
+98E4,	E1,	AMD Radeon R3 Graphics
+98E4,	E2,	AMD Radeon R3 Graphics
+98E4,	E9,	AMD Radeon R4 Graphics
+98E4,	EA,	AMD Radeon R4 Graphics
+98E4,	EB,	AMD Radeon R3 Graphics
+98E4,	EB,	AMD Radeon R4 Graphics
diff --git a/etnaviv/Makefile.sources b/etnaviv/Makefile.sources
deleted file mode 100644
index 3ff2fbe5..00000000
--- a/etnaviv/Makefile.sources
+++ /dev/null
@@ -1,12 +0,0 @@
-LIBDRM_ETNAVIV_FILES := \
-	etnaviv_device.c \
-	etnaviv_gpu.c \
-	etnaviv_bo.c \
-	etnaviv_bo_cache.c \
-	etnaviv_perfmon.c \
-	etnaviv_pipe.c \
-	etnaviv_cmd_stream.c \
-	etnaviv_priv.h
-
-LIBDRM_ETNAVIV_H_FILES := \
-	etnaviv_drmif.h
diff --git a/etnaviv/etnaviv_device.c b/etnaviv/etnaviv_device.c
index 699df256..052a2e20 100644
--- a/etnaviv/etnaviv_device.c
+++ b/etnaviv/etnaviv_device.c
@@ -25,8 +25,7 @@
  */
 
 #include <stdlib.h>
-#include <linux/stddef.h>
-#include <linux/types.h>
+#include <sys/types.h>
 #include <errno.h>
 #include <sys/mman.h>
 #include <fcntl.h>
diff --git a/etnaviv/meson.build b/etnaviv/meson.build
index 591f20f0..10861351 100644
--- a/etnaviv/meson.build
+++ b/etnaviv/meson.build
@@ -32,8 +32,8 @@ libdrm_etnaviv = library(
   link_with : libdrm,
   c_args : libdrm_c_args,
   gnu_symbol_visibility : 'hidden',
-  dependencies : [dep_pthread_stubs, dep_rt, dep_atomic_ops],
-  version : '1.0.0',
+  dependencies : [dep_threads, dep_rt, dep_atomic_ops],
+  version : '1.@0@.0'.format(patch_ver),
   install : true,
 )
 
@@ -61,6 +61,6 @@ test(
   args : [
     '--lib', libdrm_etnaviv,
     '--symbols-file', files('etnaviv-symbols.txt'),
-    '--nm', prog_nm.path(),
+    '--nm', prog_nm.full_path(),
   ],
 )
diff --git a/exynos/exynos_drm.c b/exynos/exynos_drm.c
index 3e322a17..fb4cd8de 100644
--- a/exynos/exynos_drm.c
+++ b/exynos/exynos_drm.c
@@ -31,7 +31,6 @@
 #include <unistd.h>
 
 #include <sys/mman.h>
-#include <linux/stddef.h>
 
 #include <xf86drm.h>
 
diff --git a/exynos/exynos_fimg2d.c b/exynos/exynos_fimg2d.c
index ac6fa687..f0aee962 100644
--- a/exynos/exynos_fimg2d.c
+++ b/exynos/exynos_fimg2d.c
@@ -30,7 +30,6 @@
 #include <assert.h>
 
 #include <sys/mman.h>
-#include <linux/stddef.h>
 
 #include <xf86drm.h>
 
diff --git a/exynos/meson.build b/exynos/meson.build
index 2f02ae71..6a790f49 100644
--- a/exynos/meson.build
+++ b/exynos/meson.build
@@ -25,8 +25,8 @@ libdrm_exynos = library(
   gnu_symbol_visibility : 'hidden',
   include_directories : [inc_root, inc_drm],
   link_with : libdrm,
-  dependencies : [dep_pthread_stubs],
-  version : '1.0.0',
+  dependencies : [dep_threads],
+  version : '1.@0@.0'.format(patch_ver),
   install : true,
 )
 
@@ -56,6 +56,6 @@ test(
   args : [
     '--lib', libdrm_exynos,
     '--symbols-file', files('exynos-symbols.txt'),
-    '--nm', prog_nm.path(),
+    '--nm', prog_nm.full_path(),
   ],
 )
diff --git a/freedreno/Makefile.sources b/freedreno/Makefile.sources
deleted file mode 100644
index ca89511a..00000000
--- a/freedreno/Makefile.sources
+++ /dev/null
@@ -1,25 +0,0 @@
-LIBDRM_FREEDRENO_FILES := \
-	freedreno_device.c \
-	freedreno_pipe.c \
-	freedreno_priv.h \
-	freedreno_ringbuffer.c \
-	freedreno_bo.c \
-	freedreno_bo_cache.c \
-	msm/msm_bo.c \
-	msm/msm_device.c \
-	msm/msm_pipe.c \
-	msm/msm_priv.h \
-	msm/msm_ringbuffer.c
-
-LIBDRM_FREEDRENO_KGSL_FILES := \
-	kgsl/kgsl_bo.c \
-	kgsl/kgsl_device.c \
-	kgsl/kgsl_drm.h \
-	kgsl/kgsl_pipe.c \
-	kgsl/kgsl_priv.h \
-	kgsl/kgsl_ringbuffer.c \
-	kgsl/msm_kgsl.h
-
-LIBDRM_FREEDRENO_H_FILES := \
-	freedreno_drmif.h \
-	freedreno_ringbuffer.h
diff --git a/freedreno/kgsl/kgsl_bo.c b/freedreno/kgsl/kgsl_bo.c
index 7a6af2f0..55b6e5c0 100644
--- a/freedreno/kgsl/kgsl_bo.c
+++ b/freedreno/kgsl/kgsl_bo.c
@@ -28,8 +28,6 @@
 
 #include "kgsl_priv.h"
 
-#include <linux/fb.h>
-
 static int set_memtype(struct fd_device *dev, uint32_t handle, uint32_t flags)
 {
 	struct drm_kgsl_gem_memtype req = {
diff --git a/freedreno/meson.build b/freedreno/meson.build
index de9ee148..311f5794 100644
--- a/freedreno/meson.build
+++ b/freedreno/meson.build
@@ -44,9 +44,9 @@ libdrm_freedreno = library(
   [files_freedreno, config_file],
   c_args : libdrm_c_args,
   include_directories : [inc_root, inc_drm],
-  dependencies : [dep_valgrind, dep_pthread_stubs, dep_rt, dep_atomic_ops],
+  dependencies : [dep_valgrind, dep_threads, dep_rt, dep_atomic_ops],
   link_with : libdrm,
-  version : '1.0.0',
+  version : '1.@0@.0'.format(patch_ver),
   install : true,
 )
 
@@ -77,6 +77,6 @@ test(
   args : [
     '--lib', libdrm_freedreno,
     '--symbols-file', files('freedreno-symbols.txt'),
-    '--nm', prog_nm.path(),
+    '--nm', prog_nm.full_path(),
   ],
 )
diff --git a/gen_table_fourcc.py b/gen_table_fourcc.py
index 4236fd79..1473d437 100644
--- a/gen_table_fourcc.py
+++ b/gen_table_fourcc.py
@@ -56,7 +56,7 @@ with open(towrite, "w") as f:
    that script instead of adding here entries manually! */
 static const struct drmFormatModifierInfo drm_format_modifier_table[] = {
 ''')
-    f.write('    { DRM_MODIFIER_INVALID(NONE, INVALID_MODIFIER) },\n')
+    f.write('    { DRM_MODIFIER_INVALID(NONE, INVALID) },\n')
     f.write('    { DRM_MODIFIER_LINEAR(NONE, LINEAR) },\n')
 
     for entry in fm_re['intel']:
diff --git a/include/drm/amdgpu_drm.h b/include/drm/amdgpu_drm.h
index 7f01f983..ae3f4e27 100644
--- a/include/drm/amdgpu_drm.h
+++ b/include/drm/amdgpu_drm.h
@@ -94,6 +94,9 @@ extern "C" {
  *
  * %AMDGPU_GEM_DOMAIN_OA	Ordered append, used by 3D or Compute engines
  * for appending data.
+ *
+ * %AMDGPU_GEM_DOMAIN_DOORBELL	Doorbell. It is an MMIO region for
+ * signalling user mode queues.
  */
 #define AMDGPU_GEM_DOMAIN_CPU		0x1
 #define AMDGPU_GEM_DOMAIN_GTT		0x2
@@ -101,12 +104,14 @@ extern "C" {
 #define AMDGPU_GEM_DOMAIN_GDS		0x8
 #define AMDGPU_GEM_DOMAIN_GWS		0x10
 #define AMDGPU_GEM_DOMAIN_OA		0x20
+#define AMDGPU_GEM_DOMAIN_DOORBELL	0x40
 #define AMDGPU_GEM_DOMAIN_MASK		(AMDGPU_GEM_DOMAIN_CPU | \
 					 AMDGPU_GEM_DOMAIN_GTT | \
 					 AMDGPU_GEM_DOMAIN_VRAM | \
 					 AMDGPU_GEM_DOMAIN_GDS | \
 					 AMDGPU_GEM_DOMAIN_GWS | \
-					 AMDGPU_GEM_DOMAIN_OA)
+					 AMDGPU_GEM_DOMAIN_OA | \
+					 AMDGPU_GEM_DOMAIN_DOORBELL)
 
 /* Flag that CPU access will be required for the case of VRAM domain */
 #define AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED	(1 << 0)
@@ -140,6 +145,32 @@ extern "C" {
  * not require GTT memory accounting
  */
 #define AMDGPU_GEM_CREATE_PREEMPTIBLE		(1 << 11)
+/* Flag that BO can be discarded under memory pressure without keeping the
+ * content.
+ */
+#define AMDGPU_GEM_CREATE_DISCARDABLE		(1 << 12)
+/* Flag that BO is shared coherently between multiple devices or CPU threads.
+ * May depend on GPU instructions to flush caches to system scope explicitly.
+ *
+ * This influences the choice of MTYPE in the PTEs on GFXv9 and later GPUs and
+ * may override the MTYPE selected in AMDGPU_VA_OP_MAP.
+ */
+#define AMDGPU_GEM_CREATE_COHERENT		(1 << 13)
+/* Flag that BO should not be cached by GPU. Coherent without having to flush
+ * GPU caches explicitly
+ *
+ * This influences the choice of MTYPE in the PTEs on GFXv9 and later GPUs and
+ * may override the MTYPE selected in AMDGPU_VA_OP_MAP.
+ */
+#define AMDGPU_GEM_CREATE_UNCACHED		(1 << 14)
+/* Flag that BO should be coherent across devices when using device-level
+ * atomics. May depend on GPU instructions to flush caches to device scope
+ * explicitly, promoting them to system scope automatically.
+ *
+ * This influences the choice of MTYPE in the PTEs on GFXv9 and later GPUs and
+ * may override the MTYPE selected in AMDGPU_VA_OP_MAP.
+ */
+#define AMDGPU_GEM_CREATE_EXT_COHERENT		(1 << 15)
 
 struct drm_amdgpu_gem_create_in  {
 	/** the requested memory size */
@@ -218,15 +249,17 @@ union drm_amdgpu_bo_list {
 /* unknown cause */
 #define AMDGPU_CTX_UNKNOWN_RESET	3
 
-/* indicate gpu reset occured after ctx created */
+/* indicate gpu reset occurred after ctx created */
 #define AMDGPU_CTX_QUERY2_FLAGS_RESET    (1<<0)
-/* indicate vram lost occured after ctx created */
+/* indicate vram lost occurred after ctx created */
 #define AMDGPU_CTX_QUERY2_FLAGS_VRAMLOST (1<<1)
 /* indicate some job from this context once cause gpu hang */
 #define AMDGPU_CTX_QUERY2_FLAGS_GUILTY   (1<<2)
 /* indicate some errors are detected by RAS */
 #define AMDGPU_CTX_QUERY2_FLAGS_RAS_CE   (1<<3)
 #define AMDGPU_CTX_QUERY2_FLAGS_RAS_UE   (1<<4)
+/* indicate that the reset hasn't completed yet */
+#define AMDGPU_CTX_QUERY2_FLAGS_RESET_IN_PROGRESS (1<<5)
 
 /* Context priority level */
 #define AMDGPU_CTX_PRIORITY_UNSET       -2048
@@ -359,7 +392,7 @@ struct drm_amdgpu_gem_userptr {
 #define AMDGPU_TILING_NUM_BANKS_SHIFT			21
 #define AMDGPU_TILING_NUM_BANKS_MASK			0x3
 
-/* GFX9 and later: */
+/* GFX9 - GFX11: */
 #define AMDGPU_TILING_SWIZZLE_MODE_SHIFT		0
 #define AMDGPU_TILING_SWIZZLE_MODE_MASK			0x1f
 #define AMDGPU_TILING_DCC_OFFSET_256B_SHIFT		5
@@ -373,6 +406,17 @@ struct drm_amdgpu_gem_userptr {
 #define AMDGPU_TILING_SCANOUT_SHIFT			63
 #define AMDGPU_TILING_SCANOUT_MASK			0x1
 
+/* GFX12 and later: */
+#define AMDGPU_TILING_GFX12_SWIZZLE_MODE_SHIFT			0
+#define AMDGPU_TILING_GFX12_SWIZZLE_MODE_MASK			0x7
+/* These are DCC recompression setting for memory management: */
+#define AMDGPU_TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_SHIFT	3
+#define AMDGPU_TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_MASK	0x3 /* 0:64B, 1:128B, 2:256B */
+#define AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_SHIFT		5
+#define AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_MASK		0x7 /* CB_COLOR0_INFO.NUMBER_TYPE */
+#define AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_SHIFT		8
+#define AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_MASK		0x3f /* [0:4]:CB_COLOR0_INFO.FORMAT, [5]:MM */
+
 /* Set/Get helpers for tiling flags. */
 #define AMDGPU_TILING_SET(field, value) \
 	(((__u64)(value) & AMDGPU_TILING_##field##_MASK) << AMDGPU_TILING_##field##_SHIFT)
@@ -529,6 +573,8 @@ struct drm_amdgpu_gem_op {
 #define AMDGPU_VM_MTYPE_UC		(4 << 5)
 /* Use Read Write MTYPE instead of default MTYPE */
 #define AMDGPU_VM_MTYPE_RW		(5 << 5)
+/* don't allocate MALL */
+#define AMDGPU_VM_PAGE_NOALLOC		(1 << 9)
 
 struct drm_amdgpu_gem_va {
 	/** GEM object handle */
@@ -553,9 +599,14 @@ struct drm_amdgpu_gem_va {
 #define AMDGPU_HW_IP_VCE          4
 #define AMDGPU_HW_IP_UVD_ENC      5
 #define AMDGPU_HW_IP_VCN_DEC      6
+/*
+ * From VCN4, AMDGPU_HW_IP_VCN_ENC is re-used to support
+ * both encoding and decoding jobs.
+ */
 #define AMDGPU_HW_IP_VCN_ENC      7
 #define AMDGPU_HW_IP_VCN_JPEG     8
-#define AMDGPU_HW_IP_NUM          9
+#define AMDGPU_HW_IP_VPE          9
+#define AMDGPU_HW_IP_NUM          10
 
 #define AMDGPU_HW_IP_INSTANCE_MAX_COUNT 1
 
@@ -568,6 +619,7 @@ struct drm_amdgpu_gem_va {
 #define AMDGPU_CHUNK_ID_SCHEDULED_DEPENDENCIES	0x07
 #define AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT    0x08
 #define AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_SIGNAL  0x09
+#define AMDGPU_CHUNK_ID_CP_GFX_SHADOW   0x0a
 
 struct drm_amdgpu_cs_chunk {
 	__u32		chunk_id;
@@ -684,6 +736,15 @@ struct drm_amdgpu_cs_chunk_data {
 	};
 };
 
+#define AMDGPU_CS_CHUNK_CP_GFX_SHADOW_FLAGS_INIT_SHADOW         0x1
+
+struct drm_amdgpu_cs_chunk_cp_gfx_shadow {
+	__u64 shadow_va;
+	__u64 csa_va;
+	__u64 gds_va;
+	__u64 flags;
+};
+
 /*
  *  Query h/w info: Flag that this is integrated (a.h.a. fusion) GPU
  *
@@ -691,6 +752,17 @@ struct drm_amdgpu_cs_chunk_data {
 #define AMDGPU_IDS_FLAGS_FUSION         0x1
 #define AMDGPU_IDS_FLAGS_PREEMPTION     0x2
 #define AMDGPU_IDS_FLAGS_TMZ            0x4
+#define AMDGPU_IDS_FLAGS_CONFORMANT_TRUNC_COORD 0x8
+
+/*
+ *  Query h/w info: Flag identifying VF/PF/PT mode
+ *
+ */
+#define AMDGPU_IDS_FLAGS_MODE_MASK      0x300
+#define AMDGPU_IDS_FLAGS_MODE_SHIFT     0x8
+#define AMDGPU_IDS_FLAGS_MODE_PF        0x0
+#define AMDGPU_IDS_FLAGS_MODE_VF        0x1
+#define AMDGPU_IDS_FLAGS_MODE_PT        0x2
 
 /* indicate if acceleration can be working */
 #define AMDGPU_INFO_ACCEL_WORKING		0x00
@@ -743,6 +815,20 @@ struct drm_amdgpu_cs_chunk_data {
 	#define AMDGPU_INFO_FW_DMCUB		0x14
 	/* Subquery id: Query TOC firmware version */
 	#define AMDGPU_INFO_FW_TOC		0x15
+	/* Subquery id: Query CAP firmware version */
+	#define AMDGPU_INFO_FW_CAP		0x16
+	/* Subquery id: Query GFX RLCP firmware version */
+	#define AMDGPU_INFO_FW_GFX_RLCP		0x17
+	/* Subquery id: Query GFX RLCV firmware version */
+	#define AMDGPU_INFO_FW_GFX_RLCV		0x18
+	/* Subquery id: Query MES_KIQ firmware version */
+	#define AMDGPU_INFO_FW_MES_KIQ		0x19
+	/* Subquery id: Query MES firmware version */
+	#define AMDGPU_INFO_FW_MES		0x1a
+	/* Subquery id: Query IMU firmware version */
+	#define AMDGPU_INFO_FW_IMU		0x1b
+	/* Subquery id: Query VPE firmware version */
+	#define AMDGPU_INFO_FW_VPE		0x1c
 
 /* number of bytes moved for TTM migration */
 #define AMDGPU_INFO_NUM_BYTES_MOVED		0x0f
@@ -796,6 +882,12 @@ struct drm_amdgpu_cs_chunk_data {
 	#define AMDGPU_INFO_SENSOR_STABLE_PSTATE_GFX_SCLK		0x8
 	/* Subquery id: Query GPU stable pstate memory clock */
 	#define AMDGPU_INFO_SENSOR_STABLE_PSTATE_GFX_MCLK		0x9
+	/* Subquery id: Query GPU peak pstate shader clock */
+	#define AMDGPU_INFO_SENSOR_PEAK_PSTATE_GFX_SCLK			0xa
+	/* Subquery id: Query GPU peak pstate memory clock */
+	#define AMDGPU_INFO_SENSOR_PEAK_PSTATE_GFX_MCLK			0xb
+	/* Subquery id: Query input GPU power	*/
+	#define AMDGPU_INFO_SENSOR_GPU_INPUT_POWER	0xc
 /* Number of VRAM page faults on CPU access. */
 #define AMDGPU_INFO_NUM_VRAM_CPU_PAGE_FAULTS	0x1E
 #define AMDGPU_INFO_VRAM_LOST_COUNTER		0x1F
@@ -835,6 +927,10 @@ struct drm_amdgpu_cs_chunk_data {
 	#define AMDGPU_INFO_VIDEO_CAPS_DECODE		0
 	/* Subquery id: Encode */
 	#define AMDGPU_INFO_VIDEO_CAPS_ENCODE		1
+/* Query the max number of IBs per gang per submission */
+#define AMDGPU_INFO_MAX_IBS			0x22
+/* query last page fault info */
+#define AMDGPU_INFO_GPUVM_FAULT			0x23
 
 #define AMDGPU_INFO_MMR_SE_INDEX_SHIFT	0
 #define AMDGPU_INFO_MMR_SE_INDEX_MASK	0xff
@@ -986,6 +1082,8 @@ struct drm_amdgpu_info_vbios {
 #define AMDGPU_VRAM_TYPE_DDR4  8
 #define AMDGPU_VRAM_TYPE_GDDR6 9
 #define AMDGPU_VRAM_TYPE_DDR5  10
+#define AMDGPU_VRAM_TYPE_LPDDR4 11
+#define AMDGPU_VRAM_TYPE_LPDDR5 12
 
 struct drm_amdgpu_info_device {
 	/** PCI Device ID */
@@ -1011,7 +1109,8 @@ struct drm_amdgpu_info_device {
 	__u32 enabled_rb_pipes_mask;
 	__u32 num_rb_pipes;
 	__u32 num_hw_gfx_contexts;
-	__u32 _pad;
+	/* PCIe version (the smaller of the GPU and the CPU/motherboard) */
+	__u32 pcie_gen;
 	__u64 ids_flags;
 	/** Starting virtual address for UMDs. */
 	__u64 virtual_address_offset;
@@ -1058,7 +1157,8 @@ struct drm_amdgpu_info_device {
 	__u32 gs_prim_buffer_depth;
 	/* max gs wavefront per vgt*/
 	__u32 max_gs_waves_per_vgt;
-	__u32 _pad1;
+	/* PCIe number of lanes (the smaller of the GPU and the CPU/motherboard) */
+	__u32 pcie_num_lanes;
 	/* always on cu bitmap */
 	__u32 cu_ao_bitmap[4][4];
 	/** Starting high virtual address for UMDs. */
@@ -1069,6 +1169,26 @@ struct drm_amdgpu_info_device {
 	__u32 pa_sc_tile_steering_override;
 	/* disabled TCCs */
 	__u64 tcc_disabled_mask;
+	__u64 min_engine_clock;
+	__u64 min_memory_clock;
+	/* The following fields are only set on gfx11+, older chips set 0. */
+	__u32 tcp_cache_size;       /* AKA GL0, VMEM cache */
+	__u32 num_sqc_per_wgp;
+	__u32 sqc_data_cache_size;  /* AKA SMEM cache */
+	__u32 sqc_inst_cache_size;
+	__u32 gl1c_cache_size;
+	__u32 gl2c_cache_size;
+	__u64 mall_size;            /* AKA infinity cache */
+	/* high 32 bits of the rb pipes mask */
+	__u32 enabled_rb_pipes_mask_hi;
+	/* shadow area size for gfx11 */
+	__u32 shadow_size;
+	/* shadow area base virtual alignment for gfx11 */
+	__u32 shadow_alignment;
+	/* context save area size for gfx11 */
+	__u32 csa_size;
+	/* context save area base virtual alignment for gfx11 */
+	__u32 csa_alignment;
 };
 
 struct drm_amdgpu_info_hw_ip {
@@ -1083,7 +1203,8 @@ struct drm_amdgpu_info_hw_ip {
 	__u32  ib_size_alignment;
 	/** Bitmask of available rings. Bit 0 means ring 0, etc. */
 	__u32  available_rings;
-	__u32  _pad;
+	/** version info: bits 23:16 major, 15:8 minor, 7:0 revision */
+	__u32  ip_discovery_version;
 };
 
 struct drm_amdgpu_info_num_handles {
@@ -1135,6 +1256,20 @@ struct drm_amdgpu_info_video_caps {
 	struct drm_amdgpu_info_video_codec_info codec_info[AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_COUNT];
 };
 
+#define AMDGPU_VMHUB_TYPE_MASK			0xff
+#define AMDGPU_VMHUB_TYPE_SHIFT			0
+#define AMDGPU_VMHUB_TYPE_GFX			0
+#define AMDGPU_VMHUB_TYPE_MM0			1
+#define AMDGPU_VMHUB_TYPE_MM1			2
+#define AMDGPU_VMHUB_IDX_MASK			0xff00
+#define AMDGPU_VMHUB_IDX_SHIFT			8
+
+struct drm_amdgpu_info_gpuvm_fault {
+	__u64 addr;
+	__u32 status;
+	__u32 vmhub;
+};
+
 /*
  * Supported GPU families
  */
@@ -1148,7 +1283,13 @@ struct drm_amdgpu_info_video_caps {
 #define AMDGPU_FAMILY_RV			142 /* Raven */
 #define AMDGPU_FAMILY_NV			143 /* Navi10 */
 #define AMDGPU_FAMILY_VGH			144 /* Van Gogh */
+#define AMDGPU_FAMILY_GC_11_0_0			145 /* GC 11.0.0 */
 #define AMDGPU_FAMILY_YC			146 /* Yellow Carp */
+#define AMDGPU_FAMILY_GC_11_0_1			148 /* GC 11.0.1 */
+#define AMDGPU_FAMILY_GC_10_3_6			149 /* GC 10.3.6 */
+#define AMDGPU_FAMILY_GC_10_3_7			151 /* GC 10.3.7 */
+#define AMDGPU_FAMILY_GC_11_5_0			150 /* GC 11.5.0 */
+#define AMDGPU_FAMILY_GC_12_0_0			152 /* GC 12.0.0 */
 
 #if defined(__cplusplus)
 }
diff --git a/include/drm/drm.h b/include/drm/drm.h
index 398c396f..4e4f7c2c 100644
--- a/include/drm/drm.h
+++ b/include/drm/drm.h
@@ -629,8 +629,8 @@ struct drm_gem_open {
 /**
  * DRM_CAP_VBLANK_HIGH_CRTC
  *
- * If set to 1, the kernel supports specifying a CRTC index in the high bits of
- * &drm_wait_vblank_request.type.
+ * If set to 1, the kernel supports specifying a :ref:`CRTC index<crtc_index>`
+ * in the high bits of &drm_wait_vblank_request.type.
  *
  * Starting kernel version 2.6.39, this capability is always set to 1.
  */
@@ -667,8 +667,11 @@ struct drm_gem_open {
  * Bitfield of supported PRIME sharing capabilities. See &DRM_PRIME_CAP_IMPORT
  * and &DRM_PRIME_CAP_EXPORT.
  *
- * PRIME buffers are exposed as dma-buf file descriptors. See
- * Documentation/gpu/drm-mm.rst, section "PRIME Buffer Sharing".
+ * Starting from kernel version 6.6, both &DRM_PRIME_CAP_IMPORT and
+ * &DRM_PRIME_CAP_EXPORT are always advertised.
+ *
+ * PRIME buffers are exposed as dma-buf file descriptors.
+ * See :ref:`prime_buffer_sharing`.
  */
 #define DRM_CAP_PRIME			0x5
 /**
@@ -676,6 +679,8 @@ struct drm_gem_open {
  *
  * If this bit is set in &DRM_CAP_PRIME, the driver supports importing PRIME
  * buffers via the &DRM_IOCTL_PRIME_FD_TO_HANDLE ioctl.
+ *
+ * Starting from kernel version 6.6, this bit is always set in &DRM_CAP_PRIME.
  */
 #define  DRM_PRIME_CAP_IMPORT		0x1
 /**
@@ -683,6 +688,8 @@ struct drm_gem_open {
  *
  * If this bit is set in &DRM_CAP_PRIME, the driver supports exporting PRIME
  * buffers via the &DRM_IOCTL_PRIME_HANDLE_TO_FD ioctl.
+ *
+ * Starting from kernel version 6.6, this bit is always set in &DRM_CAP_PRIME.
  */
 #define  DRM_PRIME_CAP_EXPORT		0x2
 /**
@@ -700,7 +707,8 @@ struct drm_gem_open {
 /**
  * DRM_CAP_ASYNC_PAGE_FLIP
  *
- * If set to 1, the driver supports &DRM_MODE_PAGE_FLIP_ASYNC.
+ * If set to 1, the driver supports &DRM_MODE_PAGE_FLIP_ASYNC for legacy
+ * page-flips.
  */
 #define DRM_CAP_ASYNC_PAGE_FLIP		0x7
 /**
@@ -750,17 +758,23 @@ struct drm_gem_open {
 /**
  * DRM_CAP_SYNCOBJ
  *
- * If set to 1, the driver supports sync objects. See
- * Documentation/gpu/drm-mm.rst, section "DRM Sync Objects".
+ * If set to 1, the driver supports sync objects. See :ref:`drm_sync_objects`.
  */
 #define DRM_CAP_SYNCOBJ		0x13
 /**
  * DRM_CAP_SYNCOBJ_TIMELINE
  *
  * If set to 1, the driver supports timeline operations on sync objects. See
- * Documentation/gpu/drm-mm.rst, section "DRM Sync Objects".
+ * :ref:`drm_sync_objects`.
  */
 #define DRM_CAP_SYNCOBJ_TIMELINE	0x14
+/**
+ * DRM_CAP_ATOMIC_ASYNC_PAGE_FLIP
+ *
+ * If set to 1, the driver supports &DRM_MODE_PAGE_FLIP_ASYNC for atomic
+ * commits.
+ */
+#define DRM_CAP_ATOMIC_ASYNC_PAGE_FLIP	0x15
 
 /* DRM_IOCTL_GET_CAP ioctl argument type */
 struct drm_get_cap {
@@ -830,6 +844,31 @@ struct drm_get_cap {
  */
 #define DRM_CLIENT_CAP_WRITEBACK_CONNECTORS	5
 
+/**
+ * DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT
+ *
+ * Drivers for para-virtualized hardware (e.g. vmwgfx, qxl, virtio and
+ * virtualbox) have additional restrictions for cursor planes (thus
+ * making cursor planes on those drivers not truly universal,) e.g.
+ * they need cursor planes to act like one would expect from a mouse
+ * cursor and have correctly set hotspot properties.
+ * If this client cap is not set the DRM core will hide cursor plane on
+ * those virtualized drivers because not setting it implies that the
+ * client is not capable of dealing with those extra restictions.
+ * Clients which do set cursor hotspot and treat the cursor plane
+ * like a mouse cursor should set this property.
+ * The client must enable &DRM_CLIENT_CAP_ATOMIC first.
+ *
+ * Setting this property on drivers which do not special case
+ * cursor planes (i.e. non-virtualized drivers) will return
+ * EOPNOTSUPP, which can be used by userspace to gauge
+ * requirements of the hardware/drivers they're running on.
+ *
+ * This capability is always supported for atomic-capable virtualized
+ * drivers starting from kernel version 6.6.
+ */
+#define DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT	6
+
 /* DRM_IOCTL_SET_CLIENT_CAP ioctl argument type */
 struct drm_set_client_cap {
 	__u64 capability;
@@ -881,6 +920,7 @@ struct drm_syncobj_transfer {
 #define DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL (1 << 0)
 #define DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT (1 << 1)
 #define DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE (1 << 2) /* wait for time point to become available */
+#define DRM_SYNCOBJ_WAIT_FLAGS_WAIT_DEADLINE (1 << 3) /* set fence deadline to deadline_nsec */
 struct drm_syncobj_wait {
 	__u64 handles;
 	/* absolute timeout */
@@ -889,6 +929,14 @@ struct drm_syncobj_wait {
 	__u32 flags;
 	__u32 first_signaled; /* only valid when not waiting all */
 	__u32 pad;
+	/**
+	 * @deadline_nsec - fence deadline hint
+	 *
+	 * Deadline hint, in absolute CLOCK_MONOTONIC, to set on backing
+	 * fence(s) if the DRM_SYNCOBJ_WAIT_FLAGS_WAIT_DEADLINE flag is
+	 * set.
+	 */
+	__u64 deadline_nsec;
 };
 
 struct drm_syncobj_timeline_wait {
@@ -901,6 +949,35 @@ struct drm_syncobj_timeline_wait {
 	__u32 flags;
 	__u32 first_signaled; /* only valid when not waiting all */
 	__u32 pad;
+	/**
+	 * @deadline_nsec - fence deadline hint
+	 *
+	 * Deadline hint, in absolute CLOCK_MONOTONIC, to set on backing
+	 * fence(s) if the DRM_SYNCOBJ_WAIT_FLAGS_WAIT_DEADLINE flag is
+	 * set.
+	 */
+	__u64 deadline_nsec;
+};
+
+/**
+ * struct drm_syncobj_eventfd
+ * @handle: syncobj handle.
+ * @flags: Zero to wait for the point to be signalled, or
+ *         &DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE to wait for a fence to be
+ *         available for the point.
+ * @point: syncobj timeline point (set to zero for binary syncobjs).
+ * @fd: Existing eventfd to sent events to.
+ * @pad: Must be zero.
+ *
+ * Register an eventfd to be signalled by a syncobj. The eventfd counter will
+ * be incremented by one.
+ */
+struct drm_syncobj_eventfd {
+	__u32 handle;
+	__u32 flags;
+	__u64 point;
+	__s32 fd;
+	__u32 pad;
 };
 
 
@@ -966,6 +1043,19 @@ extern "C" {
 #define DRM_IOCTL_GET_STATS             DRM_IOR( 0x06, struct drm_stats)
 #define DRM_IOCTL_SET_VERSION		DRM_IOWR(0x07, struct drm_set_version)
 #define DRM_IOCTL_MODESET_CTL           DRM_IOW(0x08, struct drm_modeset_ctl)
+/**
+ * DRM_IOCTL_GEM_CLOSE - Close a GEM handle.
+ *
+ * GEM handles are not reference-counted by the kernel. User-space is
+ * responsible for managing their lifetime. For example, if user-space imports
+ * the same memory object twice on the same DRM file description, the same GEM
+ * handle is returned by both imports, and user-space needs to ensure
+ * &DRM_IOCTL_GEM_CLOSE is performed once only. The same situation can happen
+ * when a memory object is allocated, then exported and imported again on the
+ * same DRM file description. The &DRM_IOCTL_MODE_GETFB2 IOCTL is an exception
+ * and always returns fresh new GEM handles even if an existing GEM handle
+ * already refers to the same memory object before the IOCTL is performed.
+ */
 #define DRM_IOCTL_GEM_CLOSE		DRM_IOW (0x09, struct drm_gem_close)
 #define DRM_IOCTL_GEM_FLINK		DRM_IOWR(0x0a, struct drm_gem_flink)
 #define DRM_IOCTL_GEM_OPEN		DRM_IOWR(0x0b, struct drm_gem_open)
@@ -1006,7 +1096,37 @@ extern "C" {
 #define DRM_IOCTL_UNLOCK		DRM_IOW( 0x2b, struct drm_lock)
 #define DRM_IOCTL_FINISH		DRM_IOW( 0x2c, struct drm_lock)
 
+/**
+ * DRM_IOCTL_PRIME_HANDLE_TO_FD - Convert a GEM handle to a DMA-BUF FD.
+ *
+ * User-space sets &drm_prime_handle.handle with the GEM handle to export and
+ * &drm_prime_handle.flags, and gets back a DMA-BUF file descriptor in
+ * &drm_prime_handle.fd.
+ *
+ * The export can fail for any driver-specific reason, e.g. because export is
+ * not supported for this specific GEM handle (but might be for others).
+ *
+ * Support for exporting DMA-BUFs is advertised via &DRM_PRIME_CAP_EXPORT.
+ */
 #define DRM_IOCTL_PRIME_HANDLE_TO_FD    DRM_IOWR(0x2d, struct drm_prime_handle)
+/**
+ * DRM_IOCTL_PRIME_FD_TO_HANDLE - Convert a DMA-BUF FD to a GEM handle.
+ *
+ * User-space sets &drm_prime_handle.fd with a DMA-BUF file descriptor to
+ * import, and gets back a GEM handle in &drm_prime_handle.handle.
+ * &drm_prime_handle.flags is unused.
+ *
+ * If an existing GEM handle refers to the memory object backing the DMA-BUF,
+ * that GEM handle is returned. Therefore user-space which needs to handle
+ * arbitrary DMA-BUFs must have a user-space lookup data structure to manually
+ * reference-count duplicated GEM handles. For more information see
+ * &DRM_IOCTL_GEM_CLOSE.
+ *
+ * The import can fail for any driver-specific reason, e.g. because import is
+ * only supported for DMA-BUFs allocated on this DRM device.
+ *
+ * Support for importing DMA-BUFs is advertised via &DRM_PRIME_CAP_IMPORT.
+ */
 #define DRM_IOCTL_PRIME_FD_TO_HANDLE    DRM_IOWR(0x2e, struct drm_prime_handle)
 
 #define DRM_IOCTL_AGP_ACQUIRE		DRM_IO(  0x30)
@@ -1044,10 +1164,40 @@ extern "C" {
 #define DRM_IOCTL_MODE_GETPROPBLOB	DRM_IOWR(0xAC, struct drm_mode_get_blob)
 #define DRM_IOCTL_MODE_GETFB		DRM_IOWR(0xAD, struct drm_mode_fb_cmd)
 #define DRM_IOCTL_MODE_ADDFB		DRM_IOWR(0xAE, struct drm_mode_fb_cmd)
+/**
+ * DRM_IOCTL_MODE_RMFB - Remove a framebuffer.
+ *
+ * This removes a framebuffer previously added via ADDFB/ADDFB2. The IOCTL
+ * argument is a framebuffer object ID.
+ *
+ * Warning: removing a framebuffer currently in-use on an enabled plane will
+ * disable that plane. The CRTC the plane is linked to may also be disabled
+ * (depending on driver capabilities).
+ */
 #define DRM_IOCTL_MODE_RMFB		DRM_IOWR(0xAF, unsigned int)
 #define DRM_IOCTL_MODE_PAGE_FLIP	DRM_IOWR(0xB0, struct drm_mode_crtc_page_flip)
 #define DRM_IOCTL_MODE_DIRTYFB		DRM_IOWR(0xB1, struct drm_mode_fb_dirty_cmd)
 
+/**
+ * DRM_IOCTL_MODE_CREATE_DUMB - Create a new dumb buffer object.
+ *
+ * KMS dumb buffers provide a very primitive way to allocate a buffer object
+ * suitable for scanout and map it for software rendering. KMS dumb buffers are
+ * not suitable for hardware-accelerated rendering nor video decoding. KMS dumb
+ * buffers are not suitable to be displayed on any other device than the KMS
+ * device where they were allocated from. Also see
+ * :ref:`kms_dumb_buffer_objects`.
+ *
+ * The IOCTL argument is a struct drm_mode_create_dumb.
+ *
+ * User-space is expected to create a KMS dumb buffer via this IOCTL, then add
+ * it as a KMS framebuffer via &DRM_IOCTL_MODE_ADDFB and map it via
+ * &DRM_IOCTL_MODE_MAP_DUMB.
+ *
+ * &DRM_CAP_DUMB_BUFFER indicates whether this IOCTL is supported.
+ * &DRM_CAP_DUMB_PREFERRED_DEPTH and &DRM_CAP_DUMB_PREFER_SHADOW indicate
+ * driver preferences for dumb buffers.
+ */
 #define DRM_IOCTL_MODE_CREATE_DUMB DRM_IOWR(0xB2, struct drm_mode_create_dumb)
 #define DRM_IOCTL_MODE_MAP_DUMB    DRM_IOWR(0xB3, struct drm_mode_map_dumb)
 #define DRM_IOCTL_MODE_DESTROY_DUMB    DRM_IOWR(0xB4, struct drm_mode_destroy_dumb)
@@ -1080,8 +1230,58 @@ extern "C" {
 #define DRM_IOCTL_SYNCOBJ_TRANSFER	DRM_IOWR(0xCC, struct drm_syncobj_transfer)
 #define DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL	DRM_IOWR(0xCD, struct drm_syncobj_timeline_array)
 
+/**
+ * DRM_IOCTL_MODE_GETFB2 - Get framebuffer metadata.
+ *
+ * This queries metadata about a framebuffer. User-space fills
+ * &drm_mode_fb_cmd2.fb_id as the input, and the kernels fills the rest of the
+ * struct as the output.
+ *
+ * If the client is DRM master or has &CAP_SYS_ADMIN, &drm_mode_fb_cmd2.handles
+ * will be filled with GEM buffer handles. Fresh new GEM handles are always
+ * returned, even if another GEM handle referring to the same memory object
+ * already exists on the DRM file description. The caller is responsible for
+ * removing the new handles, e.g. via the &DRM_IOCTL_GEM_CLOSE IOCTL. The same
+ * new handle will be returned for multiple planes in case they use the same
+ * memory object. Planes are valid until one has a zero handle -- this can be
+ * used to compute the number of planes.
+ *
+ * Otherwise, &drm_mode_fb_cmd2.handles will be zeroed and planes are valid
+ * until one has a zero &drm_mode_fb_cmd2.pitches.
+ *
+ * If the framebuffer has a format modifier, &DRM_MODE_FB_MODIFIERS will be set
+ * in &drm_mode_fb_cmd2.flags and &drm_mode_fb_cmd2.modifier will contain the
+ * modifier. Otherwise, user-space must ignore &drm_mode_fb_cmd2.modifier.
+ *
+ * To obtain DMA-BUF FDs for each plane without leaking GEM handles, user-space
+ * can export each handle via &DRM_IOCTL_PRIME_HANDLE_TO_FD, then immediately
+ * close each unique handle via &DRM_IOCTL_GEM_CLOSE, making sure to not
+ * double-close handles which are specified multiple times in the array.
+ */
 #define DRM_IOCTL_MODE_GETFB2		DRM_IOWR(0xCE, struct drm_mode_fb_cmd2)
 
+#define DRM_IOCTL_SYNCOBJ_EVENTFD	DRM_IOWR(0xCF, struct drm_syncobj_eventfd)
+
+/**
+ * DRM_IOCTL_MODE_CLOSEFB - Close a framebuffer.
+ *
+ * This closes a framebuffer previously added via ADDFB/ADDFB2. The IOCTL
+ * argument is a framebuffer object ID.
+ *
+ * This IOCTL is similar to &DRM_IOCTL_MODE_RMFB, except it doesn't disable
+ * planes and CRTCs. As long as the framebuffer is used by a plane, it's kept
+ * alive. When the plane no longer uses the framebuffer (because the
+ * framebuffer is replaced with another one, or the plane is disabled), the
+ * framebuffer is cleaned up.
+ *
+ * This is useful to implement flicker-free transitions between two processes.
+ *
+ * Depending on the threat model, user-space may want to ensure that the
+ * framebuffer doesn't expose any sensitive user information: closed
+ * framebuffers attached to a plane can be read back by the next DRM master.
+ */
+#define DRM_IOCTL_MODE_CLOSEFB		DRM_IOWR(0xD0, struct drm_mode_closefb)
+
 /*
  * Device specific ioctls should only be in their respective headers
  * The device specific ioctl range is from 0x40 to 0x9f.
@@ -1093,25 +1293,50 @@ extern "C" {
 #define DRM_COMMAND_BASE                0x40
 #define DRM_COMMAND_END			0xA0
 
-/*
- * Header for events written back to userspace on the drm fd.  The
- * type defines the type of event, the length specifies the total
- * length of the event (including the header), and user_data is
- * typically a 64 bit value passed with the ioctl that triggered the
- * event.  A read on the drm fd will always only return complete
- * events, that is, if for example the read buffer is 100 bytes, and
- * there are two 64 byte events pending, only one will be returned.
- *
- * Event types 0 - 0x7fffffff are generic drm events, 0x80000000 and
- * up are chipset specific.
+/**
+ * struct drm_event - Header for DRM events
+ * @type: event type.
+ * @length: total number of payload bytes (including header).
+ *
+ * This struct is a header for events written back to user-space on the DRM FD.
+ * A read on the DRM FD will always only return complete events: e.g. if the
+ * read buffer is 100 bytes large and there are two 64 byte events pending,
+ * only one will be returned.
+ *
+ * Event types 0 - 0x7fffffff are generic DRM events, 0x80000000 and
+ * up are chipset specific. Generic DRM events include &DRM_EVENT_VBLANK,
+ * &DRM_EVENT_FLIP_COMPLETE and &DRM_EVENT_CRTC_SEQUENCE.
  */
 struct drm_event {
 	__u32 type;
 	__u32 length;
 };
 
+/**
+ * DRM_EVENT_VBLANK - vertical blanking event
+ *
+ * This event is sent in response to &DRM_IOCTL_WAIT_VBLANK with the
+ * &_DRM_VBLANK_EVENT flag set.
+ *
+ * The event payload is a struct drm_event_vblank.
+ */
 #define DRM_EVENT_VBLANK 0x01
+/**
+ * DRM_EVENT_FLIP_COMPLETE - page-flip completion event
+ *
+ * This event is sent in response to an atomic commit or legacy page-flip with
+ * the &DRM_MODE_PAGE_FLIP_EVENT flag set.
+ *
+ * The event payload is a struct drm_event_vblank.
+ */
 #define DRM_EVENT_FLIP_COMPLETE 0x02
+/**
+ * DRM_EVENT_CRTC_SEQUENCE - CRTC sequence event
+ *
+ * This event is sent in response to &DRM_IOCTL_CRTC_QUEUE_SEQUENCE.
+ *
+ * The event payload is a struct drm_event_crtc_sequence.
+ */
 #define DRM_EVENT_CRTC_SEQUENCE	0x03
 
 struct drm_event_vblank {
diff --git a/include/drm/drm_fourcc.h b/include/drm/drm_fourcc.h
index 957c7be2..8a9c54b5 100644
--- a/include/drm/drm_fourcc.h
+++ b/include/drm/drm_fourcc.h
@@ -54,7 +54,7 @@ extern "C" {
  * Format modifiers may change any property of the buffer, including the number
  * of planes and/or the required allocation size. Format modifiers are
  * vendor-namespaced, and as such the relationship between a fourcc code and a
- * modifier is specific to the modifer being used. For example, some modifiers
+ * modifier is specific to the modifier being used. For example, some modifiers
  * may preserve meaning - such as number of planes - from the fourcc code,
  * whereas others may not.
  *
@@ -79,7 +79,7 @@ extern "C" {
  *   format.
  * - Higher-level programs interfacing with KMS/GBM/EGL/Vulkan/etc: these users
  *   see modifiers as opaque tokens they can check for equality and intersect.
- *   These users musn't need to know to reason about the modifier value
+ *   These users mustn't need to know to reason about the modifier value
  *   (i.e. they are not expected to extract information out of the modifier).
  *
  * Vendors should document their modifier usage in as much detail as
@@ -88,6 +88,18 @@ extern "C" {
  *
  * The authoritative list of format modifier codes is found in
  * `include/uapi/drm/drm_fourcc.h`
+ *
+ * Open Source User Waiver
+ * -----------------------
+ *
+ * Because this is the authoritative source for pixel formats and modifiers
+ * referenced by GL, Vulkan extensions and other standards and hence used both
+ * by open source and closed source driver stacks, the usual requirement for an
+ * upstream in-kernel or open source userspace user does not apply.
+ *
+ * To ensure, as much as feasible, compatibility across stacks and avoid
+ * confusion with incompatible enumerations stakeholders for all relevant driver
+ * stacks should approve additions.
  */
 
 #define fourcc_code(a, b, c, d) ((__u32)(a) | ((__u32)(b) << 8) | \
@@ -99,12 +111,42 @@ extern "C" {
 #define DRM_FORMAT_INVALID	0
 
 /* color index */
+#define DRM_FORMAT_C1		fourcc_code('C', '1', ' ', ' ') /* [7:0] C0:C1:C2:C3:C4:C5:C6:C7 1:1:1:1:1:1:1:1 eight pixels/byte */
+#define DRM_FORMAT_C2		fourcc_code('C', '2', ' ', ' ') /* [7:0] C0:C1:C2:C3 2:2:2:2 four pixels/byte */
+#define DRM_FORMAT_C4		fourcc_code('C', '4', ' ', ' ') /* [7:0] C0:C1 4:4 two pixels/byte */
 #define DRM_FORMAT_C8		fourcc_code('C', '8', ' ', ' ') /* [7:0] C */
 
-/* 8 bpp Red */
+/* 1 bpp Darkness (inverse relationship between channel value and brightness) */
+#define DRM_FORMAT_D1		fourcc_code('D', '1', ' ', ' ') /* [7:0] D0:D1:D2:D3:D4:D5:D6:D7 1:1:1:1:1:1:1:1 eight pixels/byte */
+
+/* 2 bpp Darkness (inverse relationship between channel value and brightness) */
+#define DRM_FORMAT_D2		fourcc_code('D', '2', ' ', ' ') /* [7:0] D0:D1:D2:D3 2:2:2:2 four pixels/byte */
+
+/* 4 bpp Darkness (inverse relationship between channel value and brightness) */
+#define DRM_FORMAT_D4		fourcc_code('D', '4', ' ', ' ') /* [7:0] D0:D1 4:4 two pixels/byte */
+
+/* 8 bpp Darkness (inverse relationship between channel value and brightness) */
+#define DRM_FORMAT_D8		fourcc_code('D', '8', ' ', ' ') /* [7:0] D */
+
+/* 1 bpp Red (direct relationship between channel value and brightness) */
+#define DRM_FORMAT_R1		fourcc_code('R', '1', ' ', ' ') /* [7:0] R0:R1:R2:R3:R4:R5:R6:R7 1:1:1:1:1:1:1:1 eight pixels/byte */
+
+/* 2 bpp Red (direct relationship between channel value and brightness) */
+#define DRM_FORMAT_R2		fourcc_code('R', '2', ' ', ' ') /* [7:0] R0:R1:R2:R3 2:2:2:2 four pixels/byte */
+
+/* 4 bpp Red (direct relationship between channel value and brightness) */
+#define DRM_FORMAT_R4		fourcc_code('R', '4', ' ', ' ') /* [7:0] R0:R1 4:4 two pixels/byte */
+
+/* 8 bpp Red (direct relationship between channel value and brightness) */
 #define DRM_FORMAT_R8		fourcc_code('R', '8', ' ', ' ') /* [7:0] R */
 
-/* 16 bpp Red */
+/* 10 bpp Red (direct relationship between channel value and brightness) */
+#define DRM_FORMAT_R10		fourcc_code('R', '1', '0', ' ') /* [15:0] x:R 6:10 little endian */
+
+/* 12 bpp Red (direct relationship between channel value and brightness) */
+#define DRM_FORMAT_R12		fourcc_code('R', '1', '2', ' ') /* [15:0] x:R 4:12 little endian */
+
+/* 16 bpp Red (direct relationship between channel value and brightness) */
 #define DRM_FORMAT_R16		fourcc_code('R', '1', '6', ' ') /* [15:0] R little endian */
 
 /* 16 bpp RG */
@@ -199,7 +241,9 @@ extern "C" {
 #define DRM_FORMAT_VYUY		fourcc_code('V', 'Y', 'U', 'Y') /* [31:0] Y1:Cb0:Y0:Cr0 8:8:8:8 little endian */
 
 #define DRM_FORMAT_AYUV		fourcc_code('A', 'Y', 'U', 'V') /* [31:0] A:Y:Cb:Cr 8:8:8:8 little endian */
+#define DRM_FORMAT_AVUY8888	fourcc_code('A', 'V', 'U', 'Y') /* [31:0] A:Cr:Cb:Y 8:8:8:8 little endian */
 #define DRM_FORMAT_XYUV8888	fourcc_code('X', 'Y', 'U', 'V') /* [31:0] X:Y:Cb:Cr 8:8:8:8 little endian */
+#define DRM_FORMAT_XVUY8888	fourcc_code('X', 'V', 'U', 'Y') /* [31:0] X:Cr:Cb:Y 8:8:8:8 little endian */
 #define DRM_FORMAT_VUY888	fourcc_code('V', 'U', '2', '4') /* [23:0] Cr:Cb:Y 8:8:8 little endian */
 #define DRM_FORMAT_VUY101010	fourcc_code('V', 'U', '3', '0') /* Y followed by U then V, 10:10:10. Non-linear modifier only */
 
@@ -279,6 +323,8 @@ extern "C" {
  * index 1 = Cr:Cb plane, [39:0] Cr1:Cb1:Cr0:Cb0 little endian
  */
 #define DRM_FORMAT_NV15		fourcc_code('N', 'V', '1', '5') /* 2x2 subsampled Cr:Cb plane */
+#define DRM_FORMAT_NV20		fourcc_code('N', 'V', '2', '0') /* 2x1 subsampled Cr:Cb plane */
+#define DRM_FORMAT_NV30		fourcc_code('N', 'V', '3', '0') /* non-subsampled Cr:Cb plane */
 
 /*
  * 2 plane YCbCr MSB aligned
@@ -308,6 +354,13 @@ extern "C" {
  */
 #define DRM_FORMAT_P016		fourcc_code('P', '0', '1', '6') /* 2x2 subsampled Cr:Cb plane 16 bits per channel */
 
+/* 2 plane YCbCr420.
+ * 3 10 bit components and 2 padding bits packed into 4 bytes.
+ * index 0 = Y plane, [31:0] x:Y2:Y1:Y0 2:10:10:10 little endian
+ * index 1 = Cr:Cb plane, [63:0] x:Cr2:Cb2:Cr1:x:Cb1:Cr0:Cb0 [2:10:10:10:2:10:10:10] little endian
+ */
+#define DRM_FORMAT_P030		fourcc_code('P', '0', '3', '0') /* 2x2 subsampled Cr:Cb plane 10 bits per channel packed */
+
 /* 3 plane non-subsampled (444) YCbCr
  * 16 bits per component, but only 10 bits are used and 6 bits are padded
  * index 0: Y plane, [15:0] Y:x [10:6] little endian
@@ -373,6 +426,12 @@ extern "C" {
 
 #define DRM_FORMAT_RESERVED	      ((1ULL << 56) - 1)
 
+#define fourcc_mod_get_vendor(modifier) \
+	(((modifier) >> 56) & 0xff)
+
+#define fourcc_mod_is_vendor(modifier, vendor) \
+	(fourcc_mod_get_vendor(modifier) == DRM_FORMAT_MOD_VENDOR_## vendor)
+
 #define fourcc_mod_code(vendor, val) \
 	((((__u64)DRM_FORMAT_MOD_VENDOR_## vendor) << 56) | ((val) & 0x00ffffffffffffffULL))
 
@@ -481,7 +540,7 @@ extern "C" {
  * This is a tiled layout using 4Kb tiles in row-major layout.
  * Within the tile pixels are laid out in 16 256 byte units / sub-tiles which
  * are arranged in four groups (two wide, two high) with column-major layout.
- * Each group therefore consits out of four 256 byte units, which are also laid
+ * Each group therefore consists out of four 256 byte units, which are also laid
  * out as 2x2 column-major.
  * 256 byte units are made out of four 64 byte blocks of pixels, producing
  * either a square block or a 2:1 unit.
@@ -540,7 +599,7 @@ extern "C" {
  *
  * The main surface is Y-tiled and is at plane index 0 whereas CCS is linear
  * and at index 1. The clear color is stored at index 2, and the pitch should
- * be ignored. The clear color structure is 256 bits. The first 128 bits
+ * be 64 bytes aligned. The clear color structure is 256 bits. The first 128 bits
  * represents Raw Clear Color Red, Green, Blue and Alpha color each represented
  * by 32 bits. The raw clear color is consumed by the 3d engine and generates
  * the converted clear color of size 64 bits. The first 32 bits store the Lower
@@ -553,6 +612,96 @@ extern "C" {
  */
 #define I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS_CC fourcc_mod_code(INTEL, 8)
 
+/*
+ * Intel Tile 4 layout
+ *
+ * This is a tiled layout using 4KB tiles in a row-major layout. It has the same
+ * shape as Tile Y at two granularities: 4KB (128B x 32) and 64B (16B x 4). It
+ * only differs from Tile Y at the 256B granularity in between. At this
+ * granularity, Tile Y has a shape of 16B x 32 rows, but this tiling has a shape
+ * of 64B x 8 rows.
+ */
+#define I915_FORMAT_MOD_4_TILED         fourcc_mod_code(INTEL, 9)
+
+/*
+ * Intel color control surfaces (CCS) for DG2 render compression.
+ *
+ * The main surface is Tile 4 and at plane index 0. The CCS data is stored
+ * outside of the GEM object in a reserved memory area dedicated for the
+ * storage of the CCS data for all RC/RC_CC/MC compressible GEM objects. The
+ * main surface pitch is required to be a multiple of four Tile 4 widths.
+ */
+#define I915_FORMAT_MOD_4_TILED_DG2_RC_CCS fourcc_mod_code(INTEL, 10)
+
+/*
+ * Intel color control surfaces (CCS) for DG2 media compression.
+ *
+ * The main surface is Tile 4 and at plane index 0. For semi-planar formats
+ * like NV12, the Y and UV planes are Tile 4 and are located at plane indices
+ * 0 and 1, respectively. The CCS for all planes are stored outside of the
+ * GEM object in a reserved memory area dedicated for the storage of the
+ * CCS data for all RC/RC_CC/MC compressible GEM objects. The main surface
+ * pitch is required to be a multiple of four Tile 4 widths.
+ */
+#define I915_FORMAT_MOD_4_TILED_DG2_MC_CCS fourcc_mod_code(INTEL, 11)
+
+/*
+ * Intel Color Control Surface with Clear Color (CCS) for DG2 render compression.
+ *
+ * The main surface is Tile 4 and at plane index 0. The CCS data is stored
+ * outside of the GEM object in a reserved memory area dedicated for the
+ * storage of the CCS data for all RC/RC_CC/MC compressible GEM objects. The
+ * main surface pitch is required to be a multiple of four Tile 4 widths. The
+ * clear color is stored at plane index 1 and the pitch should be 64 bytes
+ * aligned. The format of the 256 bits of clear color data matches the one used
+ * for the I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS_CC modifier, see its description
+ * for details.
+ */
+#define I915_FORMAT_MOD_4_TILED_DG2_RC_CCS_CC fourcc_mod_code(INTEL, 12)
+
+/*
+ * Intel Color Control Surfaces (CCS) for display ver. 14 render compression.
+ *
+ * The main surface is tile4 and at plane index 0, the CCS is linear and
+ * at index 1. A 64B CCS cache line corresponds to an area of 4x1 tiles in
+ * main surface. In other words, 4 bits in CCS map to a main surface cache
+ * line pair. The main surface pitch is required to be a multiple of four
+ * tile4 widths.
+ */
+#define I915_FORMAT_MOD_4_TILED_MTL_RC_CCS fourcc_mod_code(INTEL, 13)
+
+/*
+ * Intel Color Control Surfaces (CCS) for display ver. 14 media compression
+ *
+ * The main surface is tile4 and at plane index 0, the CCS is linear and
+ * at index 1. A 64B CCS cache line corresponds to an area of 4x1 tiles in
+ * main surface. In other words, 4 bits in CCS map to a main surface cache
+ * line pair. The main surface pitch is required to be a multiple of four
+ * tile4 widths. For semi-planar formats like NV12, CCS planes follow the
+ * Y and UV planes i.e., planes 0 and 1 are used for Y and UV surfaces,
+ * planes 2 and 3 for the respective CCS.
+ */
+#define I915_FORMAT_MOD_4_TILED_MTL_MC_CCS fourcc_mod_code(INTEL, 14)
+
+/*
+ * Intel Color Control Surface with Clear Color (CCS) for display ver. 14 render
+ * compression.
+ *
+ * The main surface is tile4 and is at plane index 0 whereas CCS is linear
+ * and at index 1. The clear color is stored at index 2, and the pitch should
+ * be ignored. The clear color structure is 256 bits. The first 128 bits
+ * represents Raw Clear Color Red, Green, Blue and Alpha color each represented
+ * by 32 bits. The raw clear color is consumed by the 3d engine and generates
+ * the converted clear color of size 64 bits. The first 32 bits store the Lower
+ * Converted Clear Color value and the next 32 bits store the Higher Converted
+ * Clear Color value when applicable. The Converted Clear Color values are
+ * consumed by the DE. The last 64 bits are used to store Color Discard Enable
+ * and Depth Clear Value Valid which are ignored by the DE. A CCS cache line
+ * corresponds to an area of 4x1 tiles in the main surface. The main surface
+ * pitch is required to be a multiple of 4 tile widths.
+ */
+#define I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC fourcc_mod_code(INTEL, 15)
+
 /*
  * Tiled, NV12MT, grouped in 64 (pixels) x 32 (lines) -sized macroblocks
  *
@@ -590,6 +739,28 @@ extern "C" {
  */
 #define DRM_FORMAT_MOD_QCOM_COMPRESSED	fourcc_mod_code(QCOM, 1)
 
+/*
+ * Qualcomm Tiled Format
+ *
+ * Similar to DRM_FORMAT_MOD_QCOM_COMPRESSED but not compressed.
+ * Implementation may be platform and base-format specific.
+ *
+ * Each macrotile consists of m x n (mostly 4 x 4) tiles.
+ * Pixel data pitch/stride is aligned with macrotile width.
+ * Pixel data height is aligned with macrotile height.
+ * Entire pixel data buffer is aligned with 4k(bytes).
+ */
+#define DRM_FORMAT_MOD_QCOM_TILED3	fourcc_mod_code(QCOM, 3)
+
+/*
+ * Qualcomm Alternate Tiled Format
+ *
+ * Alternate tiled format typically only used within GMEM.
+ * Implementation may be platform and base-format specific.
+ */
+#define DRM_FORMAT_MOD_QCOM_TILED2	fourcc_mod_code(QCOM, 2)
+
+
 /* Vivante framebuffer modifiers */
 
 /*
@@ -630,6 +801,35 @@ extern "C" {
  */
 #define DRM_FORMAT_MOD_VIVANTE_SPLIT_SUPER_TILED fourcc_mod_code(VIVANTE, 4)
 
+/*
+ * Vivante TS (tile-status) buffer modifiers. They can be combined with all of
+ * the color buffer tiling modifiers defined above. When TS is present it's a
+ * separate buffer containing the clear/compression status of each tile. The
+ * modifiers are defined as VIVANTE_MOD_TS_c_s, where c is the color buffer
+ * tile size in bytes covered by one entry in the status buffer and s is the
+ * number of status bits per entry.
+ * We reserve the top 8 bits of the Vivante modifier space for tile status
+ * clear/compression modifiers, as future cores might add some more TS layout
+ * variations.
+ */
+#define VIVANTE_MOD_TS_64_4               (1ULL << 48)
+#define VIVANTE_MOD_TS_64_2               (2ULL << 48)
+#define VIVANTE_MOD_TS_128_4              (3ULL << 48)
+#define VIVANTE_MOD_TS_256_4              (4ULL << 48)
+#define VIVANTE_MOD_TS_MASK               (0xfULL << 48)
+
+/*
+ * Vivante compression modifiers. Those depend on a TS modifier being present
+ * as the TS bits get reinterpreted as compression tags instead of simple
+ * clear markers when compression is enabled.
+ */
+#define VIVANTE_MOD_COMP_DEC400           (1ULL << 52)
+#define VIVANTE_MOD_COMP_MASK             (0xfULL << 52)
+
+/* Masking out the extension bits will yield the base modifier. */
+#define VIVANTE_MOD_EXT_MASK              (VIVANTE_MOD_TS_MASK | \
+                                           VIVANTE_MOD_COMP_MASK)
+
 /* NVIDIA frame buffer modifiers */
 
 /*
@@ -842,6 +1042,10 @@ drm_fourcc_canonicalize_nvidia_format_mod(__u64 modifier)
  * and UV.  Some SAND-using hardware stores UV in a separate tiled
  * image from Y to reduce the column height, which is not supported
  * with these modifiers.
+ *
+ * The DRM_FORMAT_MOD_BROADCOM_SAND128_COL_HEIGHT modifier is also
+ * supported for DRM_FORMAT_P030 where the columns remain as 128 bytes
+ * wide, but as this is a 10 bpp format that translates to 96 pixels.
  */
 
 #define DRM_FORMAT_MOD_BROADCOM_SAND32_COL_HEIGHT(v) \
@@ -899,7 +1103,7 @@ drm_fourcc_canonicalize_nvidia_format_mod(__u64 modifier)
  */
 
 /*
- * The top 4 bits (out of the 56 bits alloted for specifying vendor specific
+ * The top 4 bits (out of the 56 bits allotted for specifying vendor specific
  * modifiers) denote the category for modifiers. Currently we have three
  * categories of modifiers ie AFBC, MISC and AFRC. We can have a maximum of
  * sixteen different categories.
@@ -1215,7 +1419,7 @@ drm_fourcc_canonicalize_nvidia_format_mod(__u64 modifier)
  * Amlogic FBC Memory Saving mode
  *
  * Indicates the storage is packed when pixel size is multiple of word
- * boudaries, i.e. 8bit should be stored in this mode to save allocation
+ * boundaries, i.e. 8bit should be stored in this mode to save allocation
  * memory.
  *
  * This mode reduces body layout to 3072 bytes per 64x32 superblock with
@@ -1271,6 +1475,8 @@ drm_fourcc_canonicalize_nvidia_format_mod(__u64 modifier)
 #define AMD_FMT_MOD_TILE_VER_GFX9 1
 #define AMD_FMT_MOD_TILE_VER_GFX10 2
 #define AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS 3
+#define AMD_FMT_MOD_TILE_VER_GFX11 4
+#define AMD_FMT_MOD_TILE_VER_GFX12 5
 
 /*
  * 64K_S is the same for GFX9/GFX10/GFX10_RBPLUS and hence has GFX9 as canonical
@@ -1281,11 +1487,27 @@ drm_fourcc_canonicalize_nvidia_format_mod(__u64 modifier)
 /*
  * 64K_D for non-32 bpp is the same for GFX9/GFX10/GFX10_RBPLUS and hence has
  * GFX9 as canonical version.
+ *
+ * 64K_D_2D on GFX12 is identical to 64K_D on GFX11.
  */
 #define AMD_FMT_MOD_TILE_GFX9_64K_D 10
 #define AMD_FMT_MOD_TILE_GFX9_64K_S_X 25
 #define AMD_FMT_MOD_TILE_GFX9_64K_D_X 26
 #define AMD_FMT_MOD_TILE_GFX9_64K_R_X 27
+#define AMD_FMT_MOD_TILE_GFX11_256K_R_X 31
+
+/* Gfx12 swizzle modes:
+ *    0 - LINEAR
+ *    1 - 256B_2D  - 2D block dimensions
+ *    2 - 4KB_2D
+ *    3 - 64KB_2D
+ *    4 - 256KB_2D
+ *    5 - 4KB_3D   - 3D block dimensions
+ *    6 - 64KB_3D
+ *    7 - 256KB_3D
+ */
+#define AMD_FMT_MOD_TILE_GFX12_64K_2D 3
+#define AMD_FMT_MOD_TILE_GFX12_256K_2D 4
 
 #define AMD_FMT_MOD_DCC_BLOCK_64B 0
 #define AMD_FMT_MOD_DCC_BLOCK_128B 1
@@ -1318,6 +1540,9 @@ drm_fourcc_canonicalize_nvidia_format_mod(__u64 modifier)
 #define AMD_FMT_MOD_DCC_MAX_COMPRESSED_BLOCK_SHIFT 18
 #define AMD_FMT_MOD_DCC_MAX_COMPRESSED_BLOCK_MASK 0x3
 
+#define AMD_FMT_MOD_GFX12_DCC_MAX_COMPRESSED_BLOCK_SHIFT     3
+#define AMD_FMT_MOD_GFX12_DCC_MAX_COMPRESSED_BLOCK_MASK      0x3 /* 0:64B, 1:128B, 2:256B */
+
 /*
  * DCC supports embedding some clear colors directly in the DCC surface.
  * However, on older GPUs the rendering HW ignores the embedded clear color
@@ -1352,11 +1577,11 @@ drm_fourcc_canonicalize_nvidia_format_mod(__u64 modifier)
 #define AMD_FMT_MOD_PIPE_MASK 0x7
 
 #define AMD_FMT_MOD_SET(field, value) \
-	((uint64_t)(value) << AMD_FMT_MOD_##field##_SHIFT)
+	((__u64)(value) << AMD_FMT_MOD_##field##_SHIFT)
 #define AMD_FMT_MOD_GET(field, value) \
 	(((value) >> AMD_FMT_MOD_##field##_SHIFT) & AMD_FMT_MOD_##field##_MASK)
 #define AMD_FMT_MOD_CLEAR(field) \
-	(~((uint64_t)AMD_FMT_MOD_##field##_MASK << AMD_FMT_MOD_##field##_SHIFT))
+	(~((__u64)AMD_FMT_MOD_##field##_MASK << AMD_FMT_MOD_##field##_SHIFT))
 
 #if defined(__cplusplus)
 }
diff --git a/include/drm/drm_mode.h b/include/drm/drm_mode.h
index 9b6722d4..d390011b 100644
--- a/include/drm/drm_mode.h
+++ b/include/drm/drm_mode.h
@@ -36,10 +36,10 @@ extern "C" {
 /**
  * DOC: overview
  *
- * DRM exposes many UAPI and structure definition to have a consistent
- * and standardized interface with user.
+ * DRM exposes many UAPI and structure definitions to have a consistent
+ * and standardized interface with users.
  * Userspace can refer to these structure definitions and UAPI formats
- * to communicate to driver
+ * to communicate to drivers.
  */
 
 #define DRM_CONNECTOR_NAME_LEN	32
@@ -312,16 +312,48 @@ struct drm_mode_set_plane {
 	__u32 src_w;
 };
 
+/**
+ * struct drm_mode_get_plane - Get plane metadata.
+ *
+ * Userspace can perform a GETPLANE ioctl to retrieve information about a
+ * plane.
+ *
+ * To retrieve the number of formats supported, set @count_format_types to zero
+ * and call the ioctl. @count_format_types will be updated with the value.
+ *
+ * To retrieve these formats, allocate an array with the memory needed to store
+ * @count_format_types formats. Point @format_type_ptr to this array and call
+ * the ioctl again (with @count_format_types still set to the value returned in
+ * the first ioctl call).
+ */
 struct drm_mode_get_plane {
+	/**
+	 * @plane_id: Object ID of the plane whose information should be
+	 * retrieved. Set by caller.
+	 */
 	__u32 plane_id;
 
+	/** @crtc_id: Object ID of the current CRTC. */
 	__u32 crtc_id;
+	/** @fb_id: Object ID of the current fb. */
 	__u32 fb_id;
 
+	/**
+	 * @possible_crtcs: Bitmask of CRTC's compatible with the plane. CRTC's
+	 * are created and they receive an index, which corresponds to their
+	 * position in the bitmask. Bit N corresponds to
+	 * :ref:`CRTC index<crtc_index>` N.
+	 */
 	__u32 possible_crtcs;
+	/** @gamma_size: Never used. */
 	__u32 gamma_size;
 
+	/** @count_format_types: Number of formats. */
 	__u32 count_format_types;
+	/**
+	 * @format_type_ptr: Pointer to ``__u32`` array of formats that are
+	 * supported by the plane. These formats do not require modifiers.
+	 */
 	__u64 format_type_ptr;
 };
 
@@ -456,6 +488,9 @@ struct drm_mode_get_connector {
 	 * This is not an object ID. This is a per-type connector number. Each
 	 * (type, type_id) combination is unique across all connectors of a DRM
 	 * device.
+	 *
+	 * The (type, type_id) combination is not a stable identifier: the
+	 * type_id can change depending on the driver probe order.
 	 */
 	__u32 connector_type_id;
 
@@ -505,26 +540,78 @@ struct drm_mode_get_connector {
 /* the PROP_ATOMIC flag is used to hide properties from userspace that
  * is not aware of atomic properties.  This is mostly to work around
  * older userspace (DDX drivers) that read/write each prop they find,
- * witout being aware that this could be triggering a lengthy modeset.
+ * without being aware that this could be triggering a lengthy modeset.
  */
 #define DRM_MODE_PROP_ATOMIC        0x80000000
 
+/**
+ * struct drm_mode_property_enum - Description for an enum/bitfield entry.
+ * @value: numeric value for this enum entry.
+ * @name: symbolic name for this enum entry.
+ *
+ * See struct drm_property_enum for details.
+ */
 struct drm_mode_property_enum {
 	__u64 value;
 	char name[DRM_PROP_NAME_LEN];
 };
 
+/**
+ * struct drm_mode_get_property - Get property metadata.
+ *
+ * User-space can perform a GETPROPERTY ioctl to retrieve information about a
+ * property. The same property may be attached to multiple objects, see
+ * "Modeset Base Object Abstraction".
+ *
+ * The meaning of the @values_ptr field changes depending on the property type.
+ * See &drm_property.flags for more details.
+ *
+ * The @enum_blob_ptr and @count_enum_blobs fields are only meaningful when the
+ * property has the type &DRM_MODE_PROP_ENUM or &DRM_MODE_PROP_BITMASK. For
+ * backwards compatibility, the kernel will always set @count_enum_blobs to
+ * zero when the property has the type &DRM_MODE_PROP_BLOB. User-space must
+ * ignore these two fields if the property has a different type.
+ *
+ * User-space is expected to retrieve values and enums by performing this ioctl
+ * at least twice: the first time to retrieve the number of elements, the
+ * second time to retrieve the elements themselves.
+ *
+ * To retrieve the number of elements, set @count_values and @count_enum_blobs
+ * to zero, then call the ioctl. @count_values will be updated with the number
+ * of elements. If the property has the type &DRM_MODE_PROP_ENUM or
+ * &DRM_MODE_PROP_BITMASK, @count_enum_blobs will be updated as well.
+ *
+ * To retrieve the elements themselves, allocate an array for @values_ptr and
+ * set @count_values to its capacity. If the property has the type
+ * &DRM_MODE_PROP_ENUM or &DRM_MODE_PROP_BITMASK, allocate an array for
+ * @enum_blob_ptr and set @count_enum_blobs to its capacity. Calling the ioctl
+ * again will fill the arrays.
+ */
 struct drm_mode_get_property {
-	__u64 values_ptr; /* values and blob lengths */
-	__u64 enum_blob_ptr; /* enum and blob id ptrs */
+	/** @values_ptr: Pointer to a ``__u64`` array. */
+	__u64 values_ptr;
+	/** @enum_blob_ptr: Pointer to a struct drm_mode_property_enum array. */
+	__u64 enum_blob_ptr;
 
+	/**
+	 * @prop_id: Object ID of the property which should be retrieved. Set
+	 * by the caller.
+	 */
 	__u32 prop_id;
+	/**
+	 * @flags: ``DRM_MODE_PROP_*`` bitfield. See &drm_property.flags for
+	 * a definition of the flags.
+	 */
 	__u32 flags;
+	/**
+	 * @name: Symbolic property name. User-space should use this field to
+	 * recognize properties.
+	 */
 	char name[DRM_PROP_NAME_LEN];
 
+	/** @count_values: Number of elements in @values_ptr. */
 	__u32 count_values;
-	/* This is only used to count enum values, not blobs. The _blobs is
-	 * simply because of a historical reason, i.e. backwards compat. */
+	/** @count_enum_blobs: Number of elements in @enum_blob_ptr. */
 	__u32 count_enum_blobs;
 };
 
@@ -577,43 +664,75 @@ struct drm_mode_fb_cmd {
 };
 
 #define DRM_MODE_FB_INTERLACED	(1<<0) /* for interlaced framebuffers */
-#define DRM_MODE_FB_MODIFIERS	(1<<1) /* enables ->modifer[] */
+#define DRM_MODE_FB_MODIFIERS	(1<<1) /* enables ->modifier[] */
 
+/**
+ * struct drm_mode_fb_cmd2 - Frame-buffer metadata.
+ *
+ * This struct holds frame-buffer metadata. There are two ways to use it:
+ *
+ * - User-space can fill this struct and perform a &DRM_IOCTL_MODE_ADDFB2
+ *   ioctl to register a new frame-buffer. The new frame-buffer object ID will
+ *   be set by the kernel in @fb_id.
+ * - User-space can set @fb_id and perform a &DRM_IOCTL_MODE_GETFB2 ioctl to
+ *   fetch metadata about an existing frame-buffer.
+ *
+ * In case of planar formats, this struct allows up to 4 buffer objects with
+ * offsets and pitches per plane. The pitch and offset order are dictated by
+ * the format FourCC as defined by ``drm_fourcc.h``, e.g. NV12 is described as:
+ *
+ *     YUV 4:2:0 image with a plane of 8-bit Y samples followed by an
+ *     interleaved U/V plane containing 8-bit 2x2 subsampled colour difference
+ *     samples.
+ *
+ * So it would consist of a Y plane at ``offsets[0]`` and a UV plane at
+ * ``offsets[1]``.
+ *
+ * To accommodate tiled, compressed, etc formats, a modifier can be specified.
+ * For more information see the "Format Modifiers" section. Note that even
+ * though it looks like we have a modifier per-plane, we in fact do not. The
+ * modifier for each plane must be identical. Thus all combinations of
+ * different data layouts for multi-plane formats must be enumerated as
+ * separate modifiers.
+ *
+ * All of the entries in @handles, @pitches, @offsets and @modifier must be
+ * zero when unused. Warning, for @offsets and @modifier zero can't be used to
+ * figure out whether the entry is used or not since it's a valid value (a zero
+ * offset is common, and a zero modifier is &DRM_FORMAT_MOD_LINEAR).
+ */
 struct drm_mode_fb_cmd2 {
+	/** @fb_id: Object ID of the frame-buffer. */
 	__u32 fb_id;
+	/** @width: Width of the frame-buffer. */
 	__u32 width;
+	/** @height: Height of the frame-buffer. */
 	__u32 height;
-	__u32 pixel_format; /* fourcc code from drm_fourcc.h */
-	__u32 flags; /* see above flags */
+	/**
+	 * @pixel_format: FourCC format code, see ``DRM_FORMAT_*`` constants in
+	 * ``drm_fourcc.h``.
+	 */
+	__u32 pixel_format;
+	/**
+	 * @flags: Frame-buffer flags (see &DRM_MODE_FB_INTERLACED and
+	 * &DRM_MODE_FB_MODIFIERS).
+	 */
+	__u32 flags;
 
-	/*
-	 * In case of planar formats, this ioctl allows up to 4
-	 * buffer objects with offsets and pitches per plane.
-	 * The pitch and offset order is dictated by the fourcc,
-	 * e.g. NV12 (https://fourcc.org/yuv.php#NV12) is described as:
-	 *
-	 *   YUV 4:2:0 image with a plane of 8 bit Y samples
-	 *   followed by an interleaved U/V plane containing
-	 *   8 bit 2x2 subsampled colour difference samples.
-	 *
-	 * So it would consist of Y as offsets[0] and UV as
-	 * offsets[1].  Note that offsets[0] will generally
-	 * be 0 (but this is not required).
-	 *
-	 * To accommodate tiled, compressed, etc formats, a
-	 * modifier can be specified.  The default value of zero
-	 * indicates "native" format as specified by the fourcc.
-	 * Vendor specific modifier token.  Note that even though
-	 * it looks like we have a modifier per-plane, we in fact
-	 * do not. The modifier for each plane must be identical.
-	 * Thus all combinations of different data layouts for
-	 * multi plane formats must be enumerated as separate
-	 * modifiers.
+	/**
+	 * @handles: GEM buffer handle, one per plane. Set to 0 if the plane is
+	 * unused. The same handle can be used for multiple planes.
 	 */
 	__u32 handles[4];
-	__u32 pitches[4]; /* pitch for each plane */
-	__u32 offsets[4]; /* offset of each plane */
-	__u64 modifier[4]; /* ie, tiling, compress */
+	/** @pitches: Pitch (aka. stride) in bytes, one per plane. */
+	__u32 pitches[4];
+	/** @offsets: Offset into the buffer in bytes, one per plane. */
+	__u32 offsets[4];
+	/**
+	 * @modifier: Format modifier, one per plane. See ``DRM_FORMAT_MOD_*``
+	 * constants in ``drm_fourcc.h``. All planes must use the same
+	 * modifier. Ignored unless &DRM_MODE_FB_MODIFIERS is set in @flags.
+	 */
+	__u64 modifier[4];
 };
 
 #define DRM_MODE_FB_DIRTY_ANNOTATE_COPY 0x01
@@ -718,6 +837,11 @@ struct drm_color_ctm {
 	/*
 	 * Conversion matrix in S31.32 sign-magnitude
 	 * (not two's complement!) format.
+	 *
+	 * out   matrix    in
+	 * |R|   |0 1 2|   |R|
+	 * |G| = |3 4 5| x |G|
+	 * |B|   |6 7 8|   |B|
 	 */
 	__u64 matrix[9];
 };
@@ -733,6 +857,17 @@ struct drm_color_lut {
 	__u16 reserved;
 };
 
+/**
+ * struct drm_plane_size_hint - Plane size hints
+ *
+ * The plane SIZE_HINTS property blob contains an
+ * array of struct drm_plane_size_hint.
+ */
+struct drm_plane_size_hint {
+	__u16 width;
+	__u16 height;
+};
+
 /**
  * struct hdr_metadata_infoframe - HDR Metadata Infoframe Data.
  *
@@ -757,23 +892,23 @@ struct hdr_metadata_infoframe {
 	 * These are coded as unsigned 16-bit values in units of
 	 * 0.00002, where 0x0000 represents zero and 0xC350
 	 * represents 1.0000.
-	 * @display_primaries.x: X cordinate of color primary.
-	 * @display_primaries.y: Y cordinate of color primary.
+	 * @display_primaries.x: X coordinate of color primary.
+	 * @display_primaries.y: Y coordinate of color primary.
 	 */
 	struct {
 		__u16 x, y;
-		} display_primaries[3];
+	} display_primaries[3];
 	/**
 	 * @white_point: White Point of Colorspace Data.
 	 * These are coded as unsigned 16-bit values in units of
 	 * 0.00002, where 0x0000 represents zero and 0xC350
 	 * represents 1.0000.
-	 * @white_point.x: X cordinate of whitepoint of color primary.
-	 * @white_point.y: Y cordinate of whitepoint of color primary.
+	 * @white_point.x: X coordinate of whitepoint of color primary.
+	 * @white_point.y: Y coordinate of whitepoint of color primary.
 	 */
 	struct {
 		__u16 x, y;
-		} white_point;
+	} white_point;
 	/**
 	 * @max_display_mastering_luminance: Max Mastering Display Luminance.
 	 * This value is coded as an unsigned 16-bit value in units of 1 cd/m2,
@@ -819,12 +954,40 @@ struct hdr_output_metadata {
 	};
 };
 
+/**
+ * DRM_MODE_PAGE_FLIP_EVENT
+ *
+ * Request that the kernel sends back a vblank event (see
+ * struct drm_event_vblank) with the &DRM_EVENT_FLIP_COMPLETE type when the
+ * page-flip is done.
+ */
 #define DRM_MODE_PAGE_FLIP_EVENT 0x01
+/**
+ * DRM_MODE_PAGE_FLIP_ASYNC
+ *
+ * Request that the page-flip is performed as soon as possible, ie. with no
+ * delay due to waiting for vblank. This may cause tearing to be visible on
+ * the screen.
+ *
+ * When used with atomic uAPI, the driver will return an error if the hardware
+ * doesn't support performing an asynchronous page-flip for this update.
+ * User-space should handle this, e.g. by falling back to a regular page-flip.
+ *
+ * Note, some hardware might need to perform one last synchronous page-flip
+ * before being able to switch to asynchronous page-flips. As an exception,
+ * the driver will return success even though that first page-flip is not
+ * asynchronous.
+ */
 #define DRM_MODE_PAGE_FLIP_ASYNC 0x02
 #define DRM_MODE_PAGE_FLIP_TARGET_ABSOLUTE 0x4
 #define DRM_MODE_PAGE_FLIP_TARGET_RELATIVE 0x8
 #define DRM_MODE_PAGE_FLIP_TARGET (DRM_MODE_PAGE_FLIP_TARGET_ABSOLUTE | \
 				   DRM_MODE_PAGE_FLIP_TARGET_RELATIVE)
+/**
+ * DRM_MODE_PAGE_FLIP_FLAGS
+ *
+ * Bitmask of flags suitable for &drm_mode_crtc_page_flip_target.flags.
+ */
 #define DRM_MODE_PAGE_FLIP_FLAGS (DRM_MODE_PAGE_FLIP_EVENT | \
 				  DRM_MODE_PAGE_FLIP_ASYNC | \
 				  DRM_MODE_PAGE_FLIP_TARGET)
@@ -889,13 +1052,25 @@ struct drm_mode_crtc_page_flip_target {
 	__u64 user_data;
 };
 
-/* create a dumb scanout buffer */
+/**
+ * struct drm_mode_create_dumb - Create a KMS dumb buffer for scanout.
+ * @height: buffer height in pixels
+ * @width: buffer width in pixels
+ * @bpp: bits per pixel
+ * @flags: must be zero
+ * @handle: buffer object handle
+ * @pitch: number of bytes between two consecutive lines
+ * @size: size of the whole buffer in bytes
+ *
+ * User-space fills @height, @width, @bpp and @flags. If the IOCTL succeeds,
+ * the kernel fills @handle, @pitch and @size.
+ */
 struct drm_mode_create_dumb {
 	__u32 height;
 	__u32 width;
 	__u32 bpp;
 	__u32 flags;
-	/* handle, pitch, size will be returned */
+
 	__u32 handle;
 	__u32 pitch;
 	__u64 size;
@@ -918,11 +1093,53 @@ struct drm_mode_destroy_dumb {
 	__u32 handle;
 };
 
-/* page-flip flags are valid, plus: */
+/**
+ * DRM_MODE_ATOMIC_TEST_ONLY
+ *
+ * Do not apply the atomic commit, instead check whether the hardware supports
+ * this configuration.
+ *
+ * See &drm_mode_config_funcs.atomic_check for more details on test-only
+ * commits.
+ */
 #define DRM_MODE_ATOMIC_TEST_ONLY 0x0100
+/**
+ * DRM_MODE_ATOMIC_NONBLOCK
+ *
+ * Do not block while applying the atomic commit. The &DRM_IOCTL_MODE_ATOMIC
+ * IOCTL returns immediately instead of waiting for the changes to be applied
+ * in hardware. Note, the driver will still check that the update can be
+ * applied before retuning.
+ */
 #define DRM_MODE_ATOMIC_NONBLOCK  0x0200
+/**
+ * DRM_MODE_ATOMIC_ALLOW_MODESET
+ *
+ * Allow the update to result in temporary or transient visible artifacts while
+ * the update is being applied. Applying the update may also take significantly
+ * more time than a page flip. All visual artifacts will disappear by the time
+ * the update is completed, as signalled through the vblank event's timestamp
+ * (see struct drm_event_vblank).
+ *
+ * This flag must be set when the KMS update might cause visible artifacts.
+ * Without this flag such KMS update will return a EINVAL error. What kind of
+ * update may cause visible artifacts depends on the driver and the hardware.
+ * User-space that needs to know beforehand if an update might cause visible
+ * artifacts can use &DRM_MODE_ATOMIC_TEST_ONLY without
+ * &DRM_MODE_ATOMIC_ALLOW_MODESET to see if it fails.
+ *
+ * To the best of the driver's knowledge, visual artifacts are guaranteed to
+ * not appear when this flag is not set. Some sinks might display visual
+ * artifacts outside of the driver's control.
+ */
 #define DRM_MODE_ATOMIC_ALLOW_MODESET 0x0400
 
+/**
+ * DRM_MODE_ATOMIC_FLAGS
+ *
+ * Bitfield of flags accepted by the &DRM_IOCTL_MODE_ATOMIC IOCTL in
+ * &drm_mode_atomic.flags.
+ */
 #define DRM_MODE_ATOMIC_FLAGS (\
 		DRM_MODE_PAGE_FLIP_EVENT |\
 		DRM_MODE_PAGE_FLIP_ASYNC |\
@@ -1026,6 +1243,10 @@ struct drm_mode_destroy_blob {
  * struct drm_mode_create_lease - Create lease
  *
  * Lease mode resources, creating another drm_master.
+ *
+ * The @object_ids array must reference at least one CRTC, one connector and
+ * one plane if &DRM_CLIENT_CAP_UNIVERSAL_PLANES is enabled. Alternatively,
+ * the lease can be completely empty.
  */
 struct drm_mode_create_lease {
 	/** @object_ids: Pointer to array of object ids (__u32) */
@@ -1122,6 +1343,16 @@ struct drm_mode_rect {
 	__s32 y2;
 };
 
+/**
+ * struct drm_mode_closefb
+ * @fb_id: Framebuffer ID.
+ * @pad: Must be zero.
+ */
+struct drm_mode_closefb {
+	__u32 fb_id;
+	__u32 pad;
+};
+
 #if defined(__cplusplus)
 }
 #endif
diff --git a/include/drm/i915_drm.h b/include/drm/i915_drm.h
index 72afd94e..1de0433f 100644
--- a/include/drm/i915_drm.h
+++ b/include/drm/i915_drm.h
@@ -55,15 +55,15 @@ extern "C" {
  *	cause the related events to not be seen.
  *
  * I915_RESET_UEVENT - Event is generated just before an attempt to reset the
- *	the GPU. The value supplied with the event is always 1. NOTE: Disable
+ *	GPU. The value supplied with the event is always 1. NOTE: Disable
  *	reset via module parameter will cause this event to not be seen.
  */
 #define I915_L3_PARITY_UEVENT		"L3_PARITY_ERROR"
 #define I915_ERROR_UEVENT		"ERROR"
 #define I915_RESET_UEVENT		"RESET"
 
-/*
- * i915_user_extension: Base class for defining a chain of extensions
+/**
+ * struct i915_user_extension - Base class for defining a chain of extensions
  *
  * Many interfaces need to grow over time. In most cases we can simply
  * extend the struct and have userspace pass in more data. Another option,
@@ -76,12 +76,58 @@ extern "C" {
  * increasing complexity, and for large parts of that interface to be
  * entirely optional. The downside is more pointer chasing; chasing across
  * the boundary with pointers encapsulated inside u64.
+ *
+ * Example chaining:
+ *
+ * .. code-block:: C
+ *
+ *	struct i915_user_extension ext3 {
+ *		.next_extension = 0, // end
+ *		.name = ...,
+ *	};
+ *	struct i915_user_extension ext2 {
+ *		.next_extension = (uintptr_t)&ext3,
+ *		.name = ...,
+ *	};
+ *	struct i915_user_extension ext1 {
+ *		.next_extension = (uintptr_t)&ext2,
+ *		.name = ...,
+ *	};
+ *
+ * Typically the struct i915_user_extension would be embedded in some uAPI
+ * struct, and in this case we would feed it the head of the chain(i.e ext1),
+ * which would then apply all of the above extensions.
+ *
  */
 struct i915_user_extension {
+	/**
+	 * @next_extension:
+	 *
+	 * Pointer to the next struct i915_user_extension, or zero if the end.
+	 */
 	__u64 next_extension;
+	/**
+	 * @name: Name of the extension.
+	 *
+	 * Note that the name here is just some integer.
+	 *
+	 * Also note that the name space for this is not global for the whole
+	 * driver, but rather its scope/meaning is limited to the specific piece
+	 * of uAPI which has embedded the struct i915_user_extension.
+	 */
 	__u32 name;
-	__u32 flags; /* All undefined bits must be zero. */
-	__u32 rsvd[4]; /* Reserved for future use; must be zero. */
+	/**
+	 * @flags: MBZ
+	 *
+	 * All undefined bits must be zero.
+	 */
+	__u32 flags;
+	/**
+	 * @rsvd: MBZ
+	 *
+	 * Reserved for future use; must be zero.
+	 */
+	__u32 rsvd[4];
 };
 
 /*
@@ -108,24 +154,101 @@ enum i915_mocs_table_index {
 	I915_MOCS_CACHED,
 };
 
-/*
+/**
+ * enum drm_i915_gem_engine_class - uapi engine type enumeration
+ *
  * Different engines serve different roles, and there may be more than one
- * engine serving each role. enum drm_i915_gem_engine_class provides a
- * classification of the role of the engine, which may be used when requesting
- * operations to be performed on a certain subset of engines, or for providing
- * information about that group.
+ * engine serving each role.  This enum provides a classification of the role
+ * of the engine, which may be used when requesting operations to be performed
+ * on a certain subset of engines, or for providing information about that
+ * group.
  */
 enum drm_i915_gem_engine_class {
+	/**
+	 * @I915_ENGINE_CLASS_RENDER:
+	 *
+	 * Render engines support instructions used for 3D, Compute (GPGPU),
+	 * and programmable media workloads.  These instructions fetch data and
+	 * dispatch individual work items to threads that operate in parallel.
+	 * The threads run small programs (called "kernels" or "shaders") on
+	 * the GPU's execution units (EUs).
+	 */
 	I915_ENGINE_CLASS_RENDER	= 0,
+
+	/**
+	 * @I915_ENGINE_CLASS_COPY:
+	 *
+	 * Copy engines (also referred to as "blitters") support instructions
+	 * that move blocks of data from one location in memory to another,
+	 * or that fill a specified location of memory with fixed data.
+	 * Copy engines can perform pre-defined logical or bitwise operations
+	 * on the source, destination, or pattern data.
+	 */
 	I915_ENGINE_CLASS_COPY		= 1,
+
+	/**
+	 * @I915_ENGINE_CLASS_VIDEO:
+	 *
+	 * Video engines (also referred to as "bit stream decode" (BSD) or
+	 * "vdbox") support instructions that perform fixed-function media
+	 * decode and encode.
+	 */
 	I915_ENGINE_CLASS_VIDEO		= 2,
+
+	/**
+	 * @I915_ENGINE_CLASS_VIDEO_ENHANCE:
+	 *
+	 * Video enhancement engines (also referred to as "vebox") support
+	 * instructions related to image enhancement.
+	 */
 	I915_ENGINE_CLASS_VIDEO_ENHANCE	= 3,
 
-	/* should be kept compact */
+	/**
+	 * @I915_ENGINE_CLASS_COMPUTE:
+	 *
+	 * Compute engines support a subset of the instructions available
+	 * on render engines:  compute engines support Compute (GPGPU) and
+	 * programmable media workloads, but do not support the 3D pipeline.
+	 */
+	I915_ENGINE_CLASS_COMPUTE	= 4,
+
+	/* Values in this enum should be kept compact. */
 
+	/**
+	 * @I915_ENGINE_CLASS_INVALID:
+	 *
+	 * Placeholder value to represent an invalid engine class assignment.
+	 */
 	I915_ENGINE_CLASS_INVALID	= -1
 };
 
+/**
+ * struct i915_engine_class_instance - Engine class/instance identifier
+ *
+ * There may be more than one engine fulfilling any role within the system.
+ * Each engine of a class is given a unique instance number and therefore
+ * any engine can be specified by its class:instance tuplet. APIs that allow
+ * access to any engine in the system will use struct i915_engine_class_instance
+ * for this identification.
+ */
+struct i915_engine_class_instance {
+	/**
+	 * @engine_class:
+	 *
+	 * Engine class from enum drm_i915_gem_engine_class
+	 */
+	__u16 engine_class;
+#define I915_ENGINE_CLASS_INVALID_NONE -1
+#define I915_ENGINE_CLASS_INVALID_VIRTUAL -2
+
+	/**
+	 * @engine_instance:
+	 *
+	 * Engine instance.
+	 */
+	__u16 engine_instance;
+};
+
 /**
  * DOC: perf_events exposed by i915 through /sys/bus/event_sources/drivers/i915
  *
@@ -163,8 +286,9 @@ enum drm_i915_pmu_engine_sample {
 #define I915_PMU_REQUESTED_FREQUENCY	__I915_PMU_OTHER(1)
 #define I915_PMU_INTERRUPTS		__I915_PMU_OTHER(2)
 #define I915_PMU_RC6_RESIDENCY		__I915_PMU_OTHER(3)
+#define I915_PMU_SOFTWARE_GT_AWAKE_TIME	__I915_PMU_OTHER(4)
 
-#define I915_PMU_LAST I915_PMU_RC6_RESIDENCY
+#define I915_PMU_LAST /* Deprecated - do not use */ I915_PMU_RC6_RESIDENCY
 
 /* Each region is a minimum of 16k, and there are at most 255 of them.
  */
@@ -343,6 +467,9 @@ typedef struct _drm_i915_sarea {
 #define DRM_I915_PERF_ADD_CONFIG	0x37
 #define DRM_I915_PERF_REMOVE_CONFIG	0x38
 #define DRM_I915_QUERY			0x39
+#define DRM_I915_GEM_VM_CREATE		0x3a
+#define DRM_I915_GEM_VM_DESTROY		0x3b
+#define DRM_I915_GEM_CREATE_EXT		0x3c
 /* Must be kept compact -- no holes */
 
 #define DRM_IOCTL_I915_INIT		DRM_IOW( DRM_COMMAND_BASE + DRM_I915_INIT, drm_i915_init_t)
@@ -375,10 +502,12 @@ typedef struct _drm_i915_sarea {
 #define DRM_IOCTL_I915_GEM_ENTERVT	DRM_IO(DRM_COMMAND_BASE + DRM_I915_GEM_ENTERVT)
 #define DRM_IOCTL_I915_GEM_LEAVEVT	DRM_IO(DRM_COMMAND_BASE + DRM_I915_GEM_LEAVEVT)
 #define DRM_IOCTL_I915_GEM_CREATE	DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GEM_CREATE, struct drm_i915_gem_create)
+#define DRM_IOCTL_I915_GEM_CREATE_EXT	DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GEM_CREATE_EXT, struct drm_i915_gem_create_ext)
 #define DRM_IOCTL_I915_GEM_PREAD	DRM_IOW (DRM_COMMAND_BASE + DRM_I915_GEM_PREAD, struct drm_i915_gem_pread)
 #define DRM_IOCTL_I915_GEM_PWRITE	DRM_IOW (DRM_COMMAND_BASE + DRM_I915_GEM_PWRITE, struct drm_i915_gem_pwrite)
 #define DRM_IOCTL_I915_GEM_MMAP		DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GEM_MMAP, struct drm_i915_gem_mmap)
 #define DRM_IOCTL_I915_GEM_MMAP_GTT	DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GEM_MMAP_GTT, struct drm_i915_gem_mmap_gtt)
+#define DRM_IOCTL_I915_GEM_MMAP_OFFSET	DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GEM_MMAP_GTT, struct drm_i915_gem_mmap_offset)
 #define DRM_IOCTL_I915_GEM_SET_DOMAIN	DRM_IOW (DRM_COMMAND_BASE + DRM_I915_GEM_SET_DOMAIN, struct drm_i915_gem_set_domain)
 #define DRM_IOCTL_I915_GEM_SW_FINISH	DRM_IOW (DRM_COMMAND_BASE + DRM_I915_GEM_SW_FINISH, struct drm_i915_gem_sw_finish)
 #define DRM_IOCTL_I915_GEM_SET_TILING	DRM_IOWR (DRM_COMMAND_BASE + DRM_I915_GEM_SET_TILING, struct drm_i915_gem_set_tiling)
@@ -403,6 +532,8 @@ typedef struct _drm_i915_sarea {
 #define DRM_IOCTL_I915_PERF_ADD_CONFIG	DRM_IOW(DRM_COMMAND_BASE + DRM_I915_PERF_ADD_CONFIG, struct drm_i915_perf_oa_config)
 #define DRM_IOCTL_I915_PERF_REMOVE_CONFIG	DRM_IOW(DRM_COMMAND_BASE + DRM_I915_PERF_REMOVE_CONFIG, __u64)
 #define DRM_IOCTL_I915_QUERY			DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_QUERY, struct drm_i915_query)
+#define DRM_IOCTL_I915_GEM_VM_CREATE	DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GEM_VM_CREATE, struct drm_i915_gem_vm_control)
+#define DRM_IOCTL_I915_GEM_VM_DESTROY	DRM_IOW (DRM_COMMAND_BASE + DRM_I915_GEM_VM_DESTROY, struct drm_i915_gem_vm_control)
 
 /* Allow drivers to submit batchbuffers directly to hardware, relying
  * on the security mechanisms provided by hardware.
@@ -503,6 +634,16 @@ typedef struct drm_i915_irq_wait {
 #define   I915_SCHEDULER_CAP_PRIORITY	(1ul << 1)
 #define   I915_SCHEDULER_CAP_PREEMPTION	(1ul << 2)
 #define   I915_SCHEDULER_CAP_SEMAPHORES	(1ul << 3)
+#define   I915_SCHEDULER_CAP_ENGINE_BUSY_STATS	(1ul << 4)
+/*
+ * Indicates the 2k user priority levels are statically mapped into 3 buckets as
+ * follows:
+ *
+ * -1k to -1	Low priority
+ * 0		Normal priority
+ * 1 to 1k	Highest priority
+ */
+#define   I915_SCHEDULER_CAP_STATIC_PRIORITY_MAP	(1ul << 5)
 
 #define I915_PARAM_HUC_STATUS		 42
 
@@ -520,7 +661,7 @@ typedef struct drm_i915_irq_wait {
 #define I915_PARAM_HAS_EXEC_FENCE	 44
 
 /* Query whether DRM_I915_GEM_EXECBUFFER2 supports the ability to capture
- * user specified buffers for post-mortem debugging of GPU hangs. See
+ * user specified bufffers for post-mortem debugging of GPU hangs. See
  * EXEC_OBJECT_CAPTURE.
  */
 #define I915_PARAM_HAS_EXEC_CAPTURE	 45
@@ -586,16 +727,51 @@ typedef struct drm_i915_irq_wait {
  */
 #define I915_PARAM_MMAP_GTT_COHERENT	52
 
+/*
+ * Query whether DRM_I915_GEM_EXECBUFFER2 supports coordination of parallel
+ * execution through use of explicit fence support.
+ * See I915_EXEC_FENCE_OUT and I915_EXEC_FENCE_SUBMIT.
+ */
+#define I915_PARAM_HAS_EXEC_SUBMIT_FENCE 53
+
+/*
+ * Revision of the i915-perf uAPI. The value returned helps determine what
+ * i915-perf features are available. See drm_i915_perf_property_id.
+ */
+#define I915_PARAM_PERF_REVISION	54
+
+/* Query whether DRM_I915_GEM_EXECBUFFER2 supports supplying an array of
+ * timeline syncobj through drm_i915_gem_execbuffer_ext_timeline_fences. See
+ * I915_EXEC_USE_EXTENSIONS.
+ */
+#define I915_PARAM_HAS_EXEC_TIMELINE_FENCES 55
+
+/* Query if the kernel supports the I915_USERPTR_PROBE flag. */
+#define I915_PARAM_HAS_USERPTR_PROBE 56
+
 /* Must be kept compact -- no holes and well documented */
 
-typedef struct drm_i915_getparam {
+/**
+ * struct drm_i915_getparam - Driver parameter query structure.
+ */
+struct drm_i915_getparam {
+	/** @param: Driver parameter to query. */
 	__s32 param;
-	/*
+
+	/**
+	 * @value: Address of memory where queried value should be put.
+	 *
 	 * WARNING: Using pointers instead of fixed-size u64 means we need to write
 	 * compat32 code. Don't repeat this mistake.
 	 */
 	int *value;
-} drm_i915_getparam_t;
+};
+
+/**
+ * typedef drm_i915_getparam_t - Driver parameter query structure.
+ * See struct drm_i915_getparam.
+ */
+typedef struct drm_i915_getparam drm_i915_getparam_t;
 
 /* Ioctl to set kernel params:
  */
@@ -761,14 +937,113 @@ struct drm_i915_gem_mmap_gtt {
 	__u64 offset;
 };
 
+/**
+ * struct drm_i915_gem_mmap_offset - Retrieve an offset so we can mmap this buffer object.
+ *
+ * This struct is passed as argument to the `DRM_IOCTL_I915_GEM_MMAP_OFFSET` ioctl,
+ * and is used to retrieve the fake offset to mmap an object specified by &handle.
+ *
+ * The legacy way of using `DRM_IOCTL_I915_GEM_MMAP` is removed on gen12+.
+ * `DRM_IOCTL_I915_GEM_MMAP_GTT` is an older supported alias to this struct, but will behave
+ * as setting the &extensions to 0, and &flags to `I915_MMAP_OFFSET_GTT`.
+ */
+struct drm_i915_gem_mmap_offset {
+	/** @handle: Handle for the object being mapped. */
+	__u32 handle;
+	/** @pad: Must be zero */
+	__u32 pad;
+	/**
+	 * @offset: The fake offset to use for subsequent mmap call
+	 *
+	 * This is a fixed-size type for 32/64 compatibility.
+	 */
+	__u64 offset;
+
+	/**
+	 * @flags: Flags for extended behaviour.
+	 *
+	 * It is mandatory that one of the `MMAP_OFFSET` types
+	 * should be included:
+	 *
+	 * - `I915_MMAP_OFFSET_GTT`: Use mmap with the object bound to GTT. (Write-Combined)
+	 * - `I915_MMAP_OFFSET_WC`: Use Write-Combined caching.
+	 * - `I915_MMAP_OFFSET_WB`: Use Write-Back caching.
+	 * - `I915_MMAP_OFFSET_FIXED`: Use object placement to determine caching.
+	 *
+	 * On devices with local memory `I915_MMAP_OFFSET_FIXED` is the only valid
+	 * type. On devices without local memory, this caching mode is invalid.
+	 *
+	 * As caching mode when specifying `I915_MMAP_OFFSET_FIXED`, WC or WB will
+	 * be used, depending on the object placement on creation. WB will be used
+	 * when the object can only exist in system memory, WC otherwise.
+	 */
+	__u64 flags;
+
+#define I915_MMAP_OFFSET_GTT	0
+#define I915_MMAP_OFFSET_WC	1
+#define I915_MMAP_OFFSET_WB	2
+#define I915_MMAP_OFFSET_UC	3
+#define I915_MMAP_OFFSET_FIXED	4
+
+	/**
+	 * @extensions: Zero-terminated chain of extensions.
+	 *
+	 * No current extensions defined; mbz.
+	 */
+	__u64 extensions;
+};
+
+/**
+ * struct drm_i915_gem_set_domain - Adjust the objects write or read domain, in
+ * preparation for accessing the pages via some CPU domain.
+ *
+ * Specifying a new write or read domain will flush the object out of the
+ * previous domain(if required), before then updating the objects domain
+ * tracking with the new domain.
+ *
+ * Note this might involve waiting for the object first if it is still active on
+ * the GPU.
+ *
+ * Supported values for @read_domains and @write_domain:
+ *
+ *	- I915_GEM_DOMAIN_WC: Uncached write-combined domain
+ *	- I915_GEM_DOMAIN_CPU: CPU cache domain
+ *	- I915_GEM_DOMAIN_GTT: Mappable aperture domain
+ *
+ * All other domains are rejected.
+ *
+ * Note that for discrete, starting from DG1, this is no longer supported, and
+ * is instead rejected. On such platforms the CPU domain is effectively static,
+ * where we also only support a single &drm_i915_gem_mmap_offset cache mode,
+ * which can't be set explicitly and instead depends on the object placements,
+ * as per the below.
+ *
+ * Implicit caching rules, starting from DG1:
+ *
+ *	- If any of the object placements (see &drm_i915_gem_create_ext_memory_regions)
+ *	  contain I915_MEMORY_CLASS_DEVICE then the object will be allocated and
+ *	  mapped as write-combined only.
+ *
+ *	- Everything else is always allocated and mapped as write-back, with the
+ *	  guarantee that everything is also coherent with the GPU.
+ *
+ * Note that this is likely to change in the future again, where we might need
+ * more flexibility on future devices, so making this all explicit as part of a
+ * new &drm_i915_gem_create_ext extension is probable.
+ */
 struct drm_i915_gem_set_domain {
-	/** Handle for the object */
+	/** @handle: Handle for the object. */
 	__u32 handle;
 
-	/** New read domains */
+	/** @read_domains: New read domains. */
 	__u32 read_domains;
 
-	/** New write domain */
+	/**
+	 * @write_domain: New write domain.
+	 *
+	 * Note that having something in the write domain implies it's in the
+	 * read domain, and only that read domain.
+	 */
 	__u32 write_domain;
 };
 
@@ -872,6 +1147,7 @@ struct drm_i915_gem_exec_object {
 	__u64 offset;
 };
 
+/* DRM_IOCTL_I915_GEM_EXECBUFFER was removed in Linux 5.13 */
 struct drm_i915_gem_execbuffer {
 	/**
 	 * List of buffers to be validated with their relocations to be
@@ -918,10 +1194,16 @@ struct drm_i915_gem_exec_object2 {
 	/**
 	 * When the EXEC_OBJECT_PINNED flag is specified this is populated by
 	 * the user with the GTT offset at which this object will be pinned.
+	 *
 	 * When the I915_EXEC_NO_RELOC flag is specified this must contain the
 	 * presumed_offset of the object.
+	 *
 	 * During execbuffer2 the kernel populates it with the value of the
 	 * current GTT offset of the object, for future presumed_offset writes.
+	 *
+	 * See struct drm_i915_gem_create_ext for the rules when dealing with
+	 * alignment restrictions with I915_MEMORY_CLASS_DEVICE, on devices with
+	 * minimum page sizes, like DG2.
 	 */
 	__u64 offset;
 
@@ -970,38 +1252,119 @@ struct drm_i915_gem_exec_object2 {
 	__u64 rsvd2;
 };
 
+/**
+ * struct drm_i915_gem_exec_fence - An input or output fence for the execbuf
+ * ioctl.
+ *
+ * The request will wait for input fence to signal before submission.
+ *
+ * The returned output fence will be signaled after the completion of the
+ * request.
+ */
 struct drm_i915_gem_exec_fence {
-	/**
-	 * User's handle for a drm_syncobj to wait on or signal.
-	 */
+	/** @handle: User's handle for a drm_syncobj to wait on or signal. */
 	__u32 handle;
 
+	/**
+	 * @flags: Supported flags are:
+	 *
+	 * I915_EXEC_FENCE_WAIT:
+	 * Wait for the input fence before request submission.
+	 *
+	 * I915_EXEC_FENCE_SIGNAL:
+	 * Return request completion fence as output
+	 */
+	__u32 flags;
 #define I915_EXEC_FENCE_WAIT            (1<<0)
 #define I915_EXEC_FENCE_SIGNAL          (1<<1)
 #define __I915_EXEC_FENCE_UNKNOWN_FLAGS (-(I915_EXEC_FENCE_SIGNAL << 1))
-	__u32 flags;
 };
 
-struct drm_i915_gem_execbuffer2 {
+/**
+ * struct drm_i915_gem_execbuffer_ext_timeline_fences - Timeline fences
+ * for execbuf ioctl.
+ *
+ * This structure describes an array of drm_syncobj and associated points for
+ * timeline variants of drm_syncobj. It is invalid to append this structure to
+ * the execbuf if I915_EXEC_FENCE_ARRAY is set.
+ */
+struct drm_i915_gem_execbuffer_ext_timeline_fences {
+#define DRM_I915_GEM_EXECBUFFER_EXT_TIMELINE_FENCES 0
+	/** @base: Extension link. See struct i915_user_extension. */
+	struct i915_user_extension base;
+
+	/**
+	 * @fence_count: Number of elements in the @handles_ptr & @value_ptr
+	 * arrays.
+	 */
+	__u64 fence_count;
+
+	/**
+	 * @handles_ptr: Pointer to an array of struct drm_i915_gem_exec_fence
+	 * of length @fence_count.
+	 */
+	__u64 handles_ptr;
+
 	/**
-	 * List of gem_exec_object2 structs
+	 * @values_ptr: Pointer to an array of u64 values of length
+	 * @fence_count.
+	 * Values must be 0 for a binary drm_syncobj. A Value of 0 for a
+	 * timeline drm_syncobj is invalid as it turns a drm_syncobj into a
+	 * binary one.
 	 */
+	__u64 values_ptr;
+};
+
+/**
+ * struct drm_i915_gem_execbuffer2 - Structure for DRM_I915_GEM_EXECBUFFER2
+ * ioctl.
+ */
+struct drm_i915_gem_execbuffer2 {
+	/** @buffers_ptr: Pointer to a list of gem_exec_object2 structs */
 	__u64 buffers_ptr;
+
+	/** @buffer_count: Number of elements in @buffers_ptr array */
 	__u32 buffer_count;
 
-	/** Offset in the batchbuffer to start execution from. */
+	/**
+	 * @batch_start_offset: Offset in the batchbuffer to start execution
+	 * from.
+	 */
 	__u32 batch_start_offset;
-	/** Bytes used in batchbuffer from batch_start_offset */
+
+	/**
+	 * @batch_len: Length in bytes of the batch buffer, starting from the
+	 * @batch_start_offset. If 0, length is assumed to be the batch buffer
+	 * object size.
+	 */
 	__u32 batch_len;
+
+	/** @DR1: deprecated */
 	__u32 DR1;
+
+	/** @DR4: deprecated */
 	__u32 DR4;
+
+	/** @num_cliprects: See @cliprects_ptr */
 	__u32 num_cliprects;
+
 	/**
-	 * This is a struct drm_clip_rect *cliprects if I915_EXEC_FENCE_ARRAY
-	 * is not set.  If I915_EXEC_FENCE_ARRAY is set, then this is a
-	 * struct drm_i915_gem_exec_fence *fences.
+	 * @cliprects_ptr: Kernel clipping was a DRI1 misfeature.
+	 *
+	 * It is invalid to use this field if I915_EXEC_FENCE_ARRAY or
+	 * I915_EXEC_USE_EXTENSIONS flags are not set.
+	 *
+	 * If I915_EXEC_FENCE_ARRAY is set, then this is a pointer to an array
+	 * of &drm_i915_gem_exec_fence and @num_cliprects is the length of the
+	 * array.
+	 *
+	 * If I915_EXEC_USE_EXTENSIONS is set, then this is a pointer to a
+	 * single &i915_user_extension and num_cliprects is 0.
 	 */
 	__u64 cliprects_ptr;
+
+	/** @flags: Execbuf flags */
+	__u64 flags;
 #define I915_EXEC_RING_MASK              (0x3f)
 #define I915_EXEC_DEFAULT                (0<<0)
 #define I915_EXEC_RENDER                 (1<<0)
@@ -1019,10 +1382,6 @@ struct drm_i915_gem_execbuffer2 {
 #define I915_EXEC_CONSTANTS_REL_GENERAL (0<<6) /* default */
 #define I915_EXEC_CONSTANTS_ABSOLUTE 	(1<<6)
 #define I915_EXEC_CONSTANTS_REL_SURFACE (2<<6) /* gen4/5 only */
-	__u64 flags;
-	__u64 rsvd1; /* now used for context info */
-	__u64 rsvd2;
-};
 
 /** Resets the SO write offset registers for transform feedback on gen7. */
 #define I915_EXEC_GEN7_SOL_RESET	(1<<8)
@@ -1108,7 +1467,39 @@ struct drm_i915_gem_execbuffer2 {
  */
 #define I915_EXEC_FENCE_ARRAY   (1<<19)
 
-#define __I915_EXEC_UNKNOWN_FLAGS (-(I915_EXEC_FENCE_ARRAY<<1))
+/*
+ * Setting I915_EXEC_FENCE_SUBMIT implies that lower_32_bits(rsvd2) represent
+ * a sync_file fd to wait upon (in a nonblocking manner) prior to executing
+ * the batch.
+ *
+ * Returns -EINVAL if the sync_file fd cannot be found.
+ */
+#define I915_EXEC_FENCE_SUBMIT		(1 << 20)
+
+/*
+ * Setting I915_EXEC_USE_EXTENSIONS implies that
+ * drm_i915_gem_execbuffer2.cliprects_ptr is treated as a pointer to an linked
+ * list of i915_user_extension. Each i915_user_extension node is the base of a
+ * larger structure. The list of supported structures are listed in the
+ * drm_i915_gem_execbuffer_ext enum.
+ */
+#define I915_EXEC_USE_EXTENSIONS	(1 << 21)
+#define __I915_EXEC_UNKNOWN_FLAGS (-(I915_EXEC_USE_EXTENSIONS << 1))
+
+	/** @rsvd1: Context id */
+	__u64 rsvd1;
+
+	/**
+	 * @rsvd2: in and out sync_file file descriptors.
+	 *
+	 * When I915_EXEC_FENCE_IN or I915_EXEC_FENCE_SUBMIT flag is set, the
+	 * lower 32 bits of this field will have the in sync_file fd (input).
+	 *
+	 * When I915_EXEC_FENCE_OUT flag is set, the upper 32 bits of this
+	 * field will have the out sync_file fd (output).
+	 */
+	__u64 rsvd2;
+};
 
 #define I915_EXEC_CONTEXT_ID_MASK	(0xffffffff)
 #define i915_execbuffer2_set_context_id(eb2, context) \
@@ -1172,12 +1563,11 @@ struct drm_i915_gem_busy {
 	 * reading from the object simultaneously.
 	 *
 	 * The value of each engine class is the same as specified in the
-	 * I915_CONTEXT_SET_ENGINES parameter and via perf, i.e.
+	 * I915_CONTEXT_PARAM_ENGINES context parameter and via perf, i.e.
 	 * I915_ENGINE_CLASS_RENDER, I915_ENGINE_CLASS_COPY, etc.
-	 * reported as active itself. Some hardware may have parallel
-	 * execution engines, e.g. multiple media engines, which are
-	 * mapped to the same class identifier and so are not separately
-	 * reported for busyness.
+	 * Some hardware may have parallel execution engines, e.g. multiple
+	 * media engines, which are mapped to the same class identifier and so
+	 * are not separately reported for busyness.
 	 *
 	 * Caveat emptor:
 	 * Only the boolean result of this query is reliable; that is whether
@@ -1188,49 +1578,91 @@ struct drm_i915_gem_busy {
 };
 
 /**
- * I915_CACHING_NONE
+ * struct drm_i915_gem_caching - Set or get the caching for given object
+ * handle.
  *
- * GPU access is not coherent with cpu caches. Default for machines without an
- * LLC.
- */
-#define I915_CACHING_NONE		0
-/**
- * I915_CACHING_CACHED
+ * Allow userspace to control the GTT caching bits for a given object when the
+ * object is later mapped through the ppGTT(or GGTT on older platforms lacking
+ * ppGTT support, or if the object is used for scanout). Note that this might
+ * require unbinding the object from the GTT first, if its current caching value
+ * doesn't match.
  *
- * GPU access is coherent with cpu caches and furthermore the data is cached in
- * last-level caches shared between cpu cores and the gpu GT. Default on
- * machines with HAS_LLC.
- */
-#define I915_CACHING_CACHED		1
-/**
- * I915_CACHING_DISPLAY
+ * Note that this all changes on discrete platforms, starting from DG1, the
+ * set/get caching is no longer supported, and is now rejected.  Instead the CPU
+ * caching attributes(WB vs WC) will become an immutable creation time property
+ * for the object, along with the GTT caching level. For now we don't expose any
+ * new uAPI for this, instead on DG1 this is all implicit, although this largely
+ * shouldn't matter since DG1 is coherent by default(without any way of
+ * controlling it).
+ *
+ * Implicit caching rules, starting from DG1:
+ *
+ *     - If any of the object placements (see &drm_i915_gem_create_ext_memory_regions)
+ *       contain I915_MEMORY_CLASS_DEVICE then the object will be allocated and
+ *       mapped as write-combined only.
+ *
+ *     - Everything else is always allocated and mapped as write-back, with the
+ *       guarantee that everything is also coherent with the GPU.
  *
- * Special GPU caching mode which is coherent with the scanout engines.
- * Transparently falls back to I915_CACHING_NONE on platforms where no special
- * cache mode (like write-through or gfdt flushing) is available. The kernel
- * automatically sets this mode when using a buffer as a scanout target.
- * Userspace can manually set this mode to avoid a costly stall and clflush in
- * the hotpath of drawing the first frame.
+ * Note that this is likely to change in the future again, where we might need
+ * more flexibility on future devices, so making this all explicit as part of a
+ * new &drm_i915_gem_create_ext extension is probable.
+ *
+ * Side note: Part of the reason for this is that changing the at-allocation-time CPU
+ * caching attributes for the pages might be required(and is expensive) if we
+ * need to then CPU map the pages later with different caching attributes. This
+ * inconsistent caching behaviour, while supported on x86, is not universally
+ * supported on other architectures. So for simplicity we opt for setting
+ * everything at creation time, whilst also making it immutable, on discrete
+ * platforms.
  */
-#define I915_CACHING_DISPLAY		2
-
 struct drm_i915_gem_caching {
 	/**
-	 * Handle of the buffer to set/get the caching level of. */
+	 * @handle: Handle of the buffer to set/get the caching level.
+	 */
 	__u32 handle;
 
 	/**
-	 * Caching level to apply or return value
+	 * @caching: The GTT caching level to apply or possible return value.
 	 *
-	 * bits0-15 are for generic caching control (i.e. the above defined
-	 * values). bits16-31 are reserved for platform-specific variations
-	 * (e.g. l3$ caching on gen7). */
+	 * The supported @caching values:
+	 *
+	 * I915_CACHING_NONE:
+	 *
+	 * GPU access is not coherent with CPU caches.  Default for machines
+	 * without an LLC. This means manual flushing might be needed, if we
+	 * want GPU access to be coherent.
+	 *
+	 * I915_CACHING_CACHED:
+	 *
+	 * GPU access is coherent with CPU caches and furthermore the data is
+	 * cached in last-level caches shared between CPU cores and the GPU GT.
+	 *
+	 * I915_CACHING_DISPLAY:
+	 *
+	 * Special GPU caching mode which is coherent with the scanout engines.
+	 * Transparently falls back to I915_CACHING_NONE on platforms where no
+	 * special cache mode (like write-through or gfdt flushing) is
+	 * available. The kernel automatically sets this mode when using a
+	 * buffer as a scanout target.  Userspace can manually set this mode to
+	 * avoid a costly stall and clflush in the hotpath of drawing the first
+	 * frame.
+	 */
+#define I915_CACHING_NONE		0
+#define I915_CACHING_CACHED		1
+#define I915_CACHING_DISPLAY		2
 	__u32 caching;
 };
 
 #define I915_TILING_NONE	0
 #define I915_TILING_X		1
 #define I915_TILING_Y		2
+/*
+ * Do not add new tiling types here.  The I915_TILING_* values are for
+ * de-tiling fence registers that no longer exist on modern platforms.  Although
+ * the hardware may support new types of tiling in general (e.g., Tile4), we
+ * do not need to add them to the uapi that is specific to now-defunct ioctls.
+ */
 #define I915_TILING_LAST	I915_TILING_Y
 
 #define I915_BIT_6_SWIZZLE_NONE		0
@@ -1448,20 +1880,64 @@ struct drm_i915_gem_context_create {
 	__u32 pad;
 };
 
+/**
+ * struct drm_i915_gem_context_create_ext - Structure for creating contexts.
+ */
 struct drm_i915_gem_context_create_ext {
-	__u32 ctx_id; /* output: id of new context*/
+	/** @ctx_id: Id of the created context (output) */
+	__u32 ctx_id;
+
+	/**
+	 * @flags: Supported flags are:
+	 *
+	 * I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS:
+	 *
+	 * Extensions may be appended to this structure and driver must check
+	 * for those. See @extensions.
+	 *
+	 * I915_CONTEXT_CREATE_FLAGS_SINGLE_TIMELINE
+	 *
+	 * Created context will have single timeline.
+	 */
 	__u32 flags;
 #define I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS	(1u << 0)
+#define I915_CONTEXT_CREATE_FLAGS_SINGLE_TIMELINE	(1u << 1)
 #define I915_CONTEXT_CREATE_FLAGS_UNKNOWN \
-	(-(I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS << 1))
+	(-(I915_CONTEXT_CREATE_FLAGS_SINGLE_TIMELINE << 1))
+
+	/**
+	 * @extensions: Zero-terminated chain of extensions.
+	 *
+	 * I915_CONTEXT_CREATE_EXT_SETPARAM:
+	 * Context parameter to set or query during context creation.
+	 * See struct drm_i915_gem_context_create_ext_setparam.
+	 *
+	 * I915_CONTEXT_CREATE_EXT_CLONE:
+	 * This extension has been removed. On the off chance someone somewhere
+	 * has attempted to use it, never re-use this extension number.
+	 */
 	__u64 extensions;
+#define I915_CONTEXT_CREATE_EXT_SETPARAM 0
+#define I915_CONTEXT_CREATE_EXT_CLONE 1
 };
 
+/**
+ * struct drm_i915_gem_context_param - Context parameter to set or query.
+ */
 struct drm_i915_gem_context_param {
+	/** @ctx_id: Context id */
 	__u32 ctx_id;
+
+	/** @size: Size of the parameter @value */
 	__u32 size;
+
+	/** @param: Parameter to set or query */
 	__u64 param;
 #define I915_CONTEXT_PARAM_BAN_PERIOD	0x1
+/* I915_CONTEXT_PARAM_NO_ZEROMAP has been removed.  On the off chance
+ * someone somewhere has attempted to use it, never re-use this context
+ * param number.
+ */
 #define I915_CONTEXT_PARAM_NO_ZEROMAP	0x2
 #define I915_CONTEXT_PARAM_GTT_SIZE	0x3
 #define I915_CONTEXT_PARAM_NO_ERROR_CAPTURE	0x4
@@ -1495,20 +1971,126 @@ struct drm_i915_gem_context_param {
  * On creation, all new contexts are marked as recoverable.
  */
 #define I915_CONTEXT_PARAM_RECOVERABLE	0x8
-/* Must be kept compact -- no holes and well documented */
 
-	__u64 value;
-};
+	/*
+	 * The id of the associated virtual memory address space (ppGTT) of
+	 * this context. Can be retrieved and passed to another context
+	 * (on the same fd) for both to use the same ppGTT and so share
+	 * address layouts, and avoid reloading the page tables on context
+	 * switches between themselves.
+	 *
+	 * See DRM_I915_GEM_VM_CREATE and DRM_I915_GEM_VM_DESTROY.
+	 */
+#define I915_CONTEXT_PARAM_VM		0x9
 
-/**
- * Context SSEU programming
+/*
+ * I915_CONTEXT_PARAM_ENGINES:
  *
- * It may be necessary for either functional or performance reason to configure
- * a context to run with a reduced number of SSEU (where SSEU stands for Slice/
- * Sub-slice/EU).
+ * Bind this context to operate on this subset of available engines. Henceforth,
+ * the I915_EXEC_RING selector for DRM_IOCTL_I915_GEM_EXECBUFFER2 operates as
+ * an index into this array of engines; I915_EXEC_DEFAULT selecting engine[0]
+ * and upwards. Slots 0...N are filled in using the specified (class, instance).
+ * Use
+ *	engine_class: I915_ENGINE_CLASS_INVALID,
+ *	engine_instance: I915_ENGINE_CLASS_INVALID_NONE
+ * to specify a gap in the array that can be filled in later, e.g. by a
+ * virtual engine used for load balancing.
  *
- * This is done by configuring SSEU configuration using the below
- * @struct drm_i915_gem_context_param_sseu for every supported engine which
+ * Setting the number of engines bound to the context to 0, by passing a zero
+ * sized argument, will revert back to default settings.
+ *
+ * See struct i915_context_param_engines.
+ *
+ * Extensions:
+ *   i915_context_engines_load_balance (I915_CONTEXT_ENGINES_EXT_LOAD_BALANCE)
+ *   i915_context_engines_bond (I915_CONTEXT_ENGINES_EXT_BOND)
+ *   i915_context_engines_parallel_submit (I915_CONTEXT_ENGINES_EXT_PARALLEL_SUBMIT)
+ */
+#define I915_CONTEXT_PARAM_ENGINES	0xa
+
+/*
+ * I915_CONTEXT_PARAM_PERSISTENCE:
+ *
+ * Allow the context and active rendering to survive the process until
+ * completion. Persistence allows fire-and-forget clients to queue up a
+ * bunch of work, hand the output over to a display server and then quit.
+ * If the context is marked as not persistent, upon closing (either via
+ * an explicit DRM_I915_GEM_CONTEXT_DESTROY or implicitly from file closure
+ * or process termination), the context and any outstanding requests will be
+ * cancelled (and exported fences for cancelled requests marked as -EIO).
+ *
+ * By default, new contexts allow persistence.
+ */
+#define I915_CONTEXT_PARAM_PERSISTENCE	0xb
+
+/* This API has been removed.  On the off chance someone somewhere has
+ * attempted to use it, never re-use this context param number.
+ */
+#define I915_CONTEXT_PARAM_RINGSIZE	0xc
+
+/*
+ * I915_CONTEXT_PARAM_PROTECTED_CONTENT:
+ *
+ * Mark that the context makes use of protected content, which will result
+ * in the context being invalidated when the protected content session is.
+ * Given that the protected content session is killed on suspend, the device
+ * is kept awake for the lifetime of a protected context, so the user should
+ * make sure to dispose of them once done.
+ * This flag can only be set at context creation time and, when set to true,
+ * must be preceded by an explicit setting of I915_CONTEXT_PARAM_RECOVERABLE
+ * to false. This flag can't be set to true in conjunction with setting the
+ * I915_CONTEXT_PARAM_BANNABLE flag to false. Creation example:
+ *
+ * .. code-block:: C
+ *
+ *	struct drm_i915_gem_context_create_ext_setparam p_protected = {
+ *		.base = {
+ *			.name = I915_CONTEXT_CREATE_EXT_SETPARAM,
+ *		},
+ *		.param = {
+ *			.param = I915_CONTEXT_PARAM_PROTECTED_CONTENT,
+ *			.value = 1,
+ *		}
+ *	};
+ *	struct drm_i915_gem_context_create_ext_setparam p_norecover = {
+ *		.base = {
+ *			.name = I915_CONTEXT_CREATE_EXT_SETPARAM,
+ *			.next_extension = to_user_pointer(&p_protected),
+ *		},
+ *		.param = {
+ *			.param = I915_CONTEXT_PARAM_RECOVERABLE,
+ *			.value = 0,
+ *		}
+ *	};
+ *	struct drm_i915_gem_context_create_ext create = {
+ *		.flags = I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS,
+ *		.extensions = to_user_pointer(&p_norecover);
+ *	};
+ *
+ *	ctx_id = gem_context_create_ext(drm_fd, &create);
+ *
+ * In addition to the normal failure cases, setting this flag during context
+ * creation can result in the following errors:
+ *
+ * -ENODEV: feature not available
+ * -EPERM: trying to mark a recoverable or not bannable context as protected
+ */
+#define I915_CONTEXT_PARAM_PROTECTED_CONTENT    0xd
+/* Must be kept compact -- no holes and well documented */
+
+	/** @value: Context parameter value to be set or queried */
+	__u64 value;
+};
+
+/*
+ * Context SSEU programming
+ *
+ * It may be necessary for either functional or performance reason to configure
+ * a context to run with a reduced number of SSEU (where SSEU stands for Slice/
+ * Sub-slice/EU).
+ *
+ * This is done by configuring SSEU configuration using the below
+ * @struct drm_i915_gem_context_param_sseu for every supported engine which
  * userspace intends to use.
  *
  * Not all GPUs or engines support this functionality in which case an error
@@ -1525,13 +2107,13 @@ struct drm_i915_gem_context_param_sseu {
 	/*
 	 * Engine class & instance to be configured or queried.
 	 */
-	__u16 engine_class;
-	__u16 engine_instance;
+	struct i915_engine_class_instance engine;
 
 	/*
-	 * Unused for now. Must be cleared to zero.
+	 * Unknown flags must be cleared to zero.
 	 */
 	__u32 flags;
+#define I915_CONTEXT_SSEU_FLAG_ENGINE_INDEX (1u << 0)
 
 	/*
 	 * Mask of slices to enable for the context. Valid values are a subset
@@ -1559,9 +2141,354 @@ struct drm_i915_gem_context_param_sseu {
 	__u32 rsvd;
 };
 
+/**
+ * DOC: Virtual Engine uAPI
+ *
+ * Virtual engine is a concept where userspace is able to configure a set of
+ * physical engines, submit a batch buffer, and let the driver execute it on any
+ * engine from the set as it sees fit.
+ *
+ * This is primarily useful on parts which have multiple instances of a same
+ * class engine, like for example GT3+ Skylake parts with their two VCS engines.
+ *
+ * For instance userspace can enumerate all engines of a certain class using the
+ * previously described `Engine Discovery uAPI`_. After that userspace can
+ * create a GEM context with a placeholder slot for the virtual engine (using
+ * `I915_ENGINE_CLASS_INVALID` and `I915_ENGINE_CLASS_INVALID_NONE` for class
+ * and instance respectively) and finally using the
+ * `I915_CONTEXT_ENGINES_EXT_LOAD_BALANCE` extension place a virtual engine in
+ * the same reserved slot.
+ *
+ * Example of creating a virtual engine and submitting a batch buffer to it:
+ *
+ * .. code-block:: C
+ *
+ * 	I915_DEFINE_CONTEXT_ENGINES_LOAD_BALANCE(virtual, 2) = {
+ * 		.base.name = I915_CONTEXT_ENGINES_EXT_LOAD_BALANCE,
+ * 		.engine_index = 0, // Place this virtual engine into engine map slot 0
+ * 		.num_siblings = 2,
+ * 		.engines = { { I915_ENGINE_CLASS_VIDEO, 0 },
+ * 			     { I915_ENGINE_CLASS_VIDEO, 1 }, },
+ * 	};
+ * 	I915_DEFINE_CONTEXT_PARAM_ENGINES(engines, 1) = {
+ * 		.engines = { { I915_ENGINE_CLASS_INVALID,
+ * 			       I915_ENGINE_CLASS_INVALID_NONE } },
+ * 		.extensions = to_user_pointer(&virtual), // Chains after load_balance extension
+ * 	};
+ * 	struct drm_i915_gem_context_create_ext_setparam p_engines = {
+ * 		.base = {
+ * 			.name = I915_CONTEXT_CREATE_EXT_SETPARAM,
+ * 		},
+ * 		.param = {
+ * 			.param = I915_CONTEXT_PARAM_ENGINES,
+ * 			.value = to_user_pointer(&engines),
+ * 			.size = sizeof(engines),
+ * 		},
+ * 	};
+ * 	struct drm_i915_gem_context_create_ext create = {
+ * 		.flags = I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS,
+ * 		.extensions = to_user_pointer(&p_engines);
+ * 	};
+ *
+ * 	ctx_id = gem_context_create_ext(drm_fd, &create);
+ *
+ * 	// Now we have created a GEM context with its engine map containing a
+ * 	// single virtual engine. Submissions to this slot can go either to
+ * 	// vcs0 or vcs1, depending on the load balancing algorithm used inside
+ * 	// the driver. The load balancing is dynamic from one batch buffer to
+ * 	// another and transparent to userspace.
+ *
+ * 	...
+ * 	execbuf.rsvd1 = ctx_id;
+ * 	execbuf.flags = 0; // Submits to index 0 which is the virtual engine
+ * 	gem_execbuf(drm_fd, &execbuf);
+ */
+
+/*
+ * i915_context_engines_load_balance:
+ *
+ * Enable load balancing across this set of engines.
+ *
+ * Into the I915_EXEC_DEFAULT slot [0], a virtual engine is created that when
+ * used will proxy the execbuffer request onto one of the set of engines
+ * in such a way as to distribute the load evenly across the set.
+ *
+ * The set of engines must be compatible (e.g. the same HW class) as they
+ * will share the same logical GPU context and ring.
+ *
+ * To intermix rendering with the virtual engine and direct rendering onto
+ * the backing engines (bypassing the load balancing proxy), the context must
+ * be defined to use a single timeline for all engines.
+ */
+struct i915_context_engines_load_balance {
+	struct i915_user_extension base;
+
+	__u16 engine_index;
+	__u16 num_siblings;
+	__u32 flags; /* all undefined flags must be zero */
+
+	__u64 mbz64; /* reserved for future use; must be zero */
+
+	struct i915_engine_class_instance engines[];
+} __attribute__((packed));
+
+#define I915_DEFINE_CONTEXT_ENGINES_LOAD_BALANCE(name__, N__) struct { \
+	struct i915_user_extension base; \
+	__u16 engine_index; \
+	__u16 num_siblings; \
+	__u32 flags; \
+	__u64 mbz64; \
+	struct i915_engine_class_instance engines[N__]; \
+} __attribute__((packed)) name__
+
+/*
+ * i915_context_engines_bond:
+ *
+ * Constructed bonded pairs for execution within a virtual engine.
+ *
+ * All engines are equal, but some are more equal than others. Given
+ * the distribution of resources in the HW, it may be preferable to run
+ * a request on a given subset of engines in parallel to a request on a
+ * specific engine. We enable this selection of engines within a virtual
+ * engine by specifying bonding pairs, for any given master engine we will
+ * only execute on one of the corresponding siblings within the virtual engine.
+ *
+ * To execute a request in parallel on the master engine and a sibling requires
+ * coordination with a I915_EXEC_FENCE_SUBMIT.
+ */
+struct i915_context_engines_bond {
+	struct i915_user_extension base;
+
+	struct i915_engine_class_instance master;
+
+	__u16 virtual_index; /* index of virtual engine in ctx->engines[] */
+	__u16 num_bonds;
+
+	__u64 flags; /* all undefined flags must be zero */
+	__u64 mbz64[4]; /* reserved for future use; must be zero */
+
+	struct i915_engine_class_instance engines[];
+} __attribute__((packed));
+
+#define I915_DEFINE_CONTEXT_ENGINES_BOND(name__, N__) struct { \
+	struct i915_user_extension base; \
+	struct i915_engine_class_instance master; \
+	__u16 virtual_index; \
+	__u16 num_bonds; \
+	__u64 flags; \
+	__u64 mbz64[4]; \
+	struct i915_engine_class_instance engines[N__]; \
+} __attribute__((packed)) name__
+
+/**
+ * struct i915_context_engines_parallel_submit - Configure engine for
+ * parallel submission.
+ *
+ * Setup a slot in the context engine map to allow multiple BBs to be submitted
+ * in a single execbuf IOCTL. Those BBs will then be scheduled to run on the GPU
+ * in parallel. Multiple hardware contexts are created internally in the i915 to
+ * run these BBs. Once a slot is configured for N BBs only N BBs can be
+ * submitted in each execbuf IOCTL and this is implicit behavior e.g. The user
+ * doesn't tell the execbuf IOCTL there are N BBs, the execbuf IOCTL knows how
+ * many BBs there are based on the slot's configuration. The N BBs are the last
+ * N buffer objects or first N if I915_EXEC_BATCH_FIRST is set.
+ *
+ * The default placement behavior is to create implicit bonds between each
+ * context if each context maps to more than 1 physical engine (e.g. context is
+ * a virtual engine). Also we only allow contexts of same engine class and these
+ * contexts must be in logically contiguous order. Examples of the placement
+ * behavior are described below. Lastly, the default is to not allow BBs to be
+ * preempted mid-batch. Rather insert coordinated preemption points on all
+ * hardware contexts between each set of BBs. Flags could be added in the future
+ * to change both of these default behaviors.
+ *
+ * Returns -EINVAL if hardware context placement configuration is invalid or if
+ * the placement configuration isn't supported on the platform / submission
+ * interface.
+ * Returns -ENODEV if extension isn't supported on the platform / submission
+ * interface.
+ *
+ * .. code-block:: none
+ *
+ *	Examples syntax:
+ *	CS[X] = generic engine of same class, logical instance X
+ *	INVALID = I915_ENGINE_CLASS_INVALID, I915_ENGINE_CLASS_INVALID_NONE
+ *
+ *	Example 1 pseudo code:
+ *	set_engines(INVALID)
+ *	set_parallel(engine_index=0, width=2, num_siblings=1,
+ *		     engines=CS[0],CS[1])
+ *
+ *	Results in the following valid placement:
+ *	CS[0], CS[1]
+ *
+ *	Example 2 pseudo code:
+ *	set_engines(INVALID)
+ *	set_parallel(engine_index=0, width=2, num_siblings=2,
+ *		     engines=CS[0],CS[2],CS[1],CS[3])
+ *
+ *	Results in the following valid placements:
+ *	CS[0], CS[1]
+ *	CS[2], CS[3]
+ *
+ *	This can be thought of as two virtual engines, each containing two
+ *	engines thereby making a 2D array. However, there are bonds tying the
+ *	entries together and placing restrictions on how they can be scheduled.
+ *	Specifically, the scheduler can choose only vertical columns from the 2D
+ *	array. That is, CS[0] is bonded to CS[1] and CS[2] to CS[3]. So if the
+ *	scheduler wants to submit to CS[0], it must also choose CS[1] and vice
+ *	versa. Same for CS[2] requires also using CS[3].
+ *	VE[0] = CS[0], CS[2]
+ *	VE[1] = CS[1], CS[3]
+ *
+ *	Example 3 pseudo code:
+ *	set_engines(INVALID)
+ *	set_parallel(engine_index=0, width=2, num_siblings=2,
+ *		     engines=CS[0],CS[1],CS[1],CS[3])
+ *
+ *	Results in the following valid and invalid placements:
+ *	CS[0], CS[1]
+ *	CS[1], CS[3] - Not logically contiguous, return -EINVAL
+ */
+struct i915_context_engines_parallel_submit {
+	/**
+	 * @base: base user extension.
+	 */
+	struct i915_user_extension base;
+
+	/**
+	 * @engine_index: slot for parallel engine
+	 */
+	__u16 engine_index;
+
+	/**
+	 * @width: number of contexts per parallel engine or in other words the
+	 * number of batches in each submission
+	 */
+	__u16 width;
+
+	/**
+	 * @num_siblings: number of siblings per context or in other words the
+	 * number of possible placements for each submission
+	 */
+	__u16 num_siblings;
+
+	/**
+	 * @mbz16: reserved for future use; must be zero
+	 */
+	__u16 mbz16;
+
+	/**
+	 * @flags: all undefined flags must be zero, currently not defined flags
+	 */
+	__u64 flags;
+
+	/**
+	 * @mbz64: reserved for future use; must be zero
+	 */
+	__u64 mbz64[3];
+
+	/**
+	 * @engines: 2-d array of engine instances to configure parallel engine
+	 *
+	 * length = width (i) * num_siblings (j)
+	 * index = j + i * num_siblings
+	 */
+	struct i915_engine_class_instance engines[];
+
+} __attribute__((packed));
+
+#define I915_DEFINE_CONTEXT_ENGINES_PARALLEL_SUBMIT(name__, N__) struct { \
+	struct i915_user_extension base; \
+	__u16 engine_index; \
+	__u16 width; \
+	__u16 num_siblings; \
+	__u16 mbz16; \
+	__u64 flags; \
+	__u64 mbz64[3]; \
+	struct i915_engine_class_instance engines[N__]; \
+} __attribute__((packed)) name__
+
+/**
+ * DOC: Context Engine Map uAPI
+ *
+ * Context engine map is a new way of addressing engines when submitting batch-
+ * buffers, replacing the existing way of using identifiers like `I915_EXEC_BLT`
+ * inside the flags field of `struct drm_i915_gem_execbuffer2`.
+ *
+ * To use it created GEM contexts need to be configured with a list of engines
+ * the user is intending to submit to. This is accomplished using the
+ * `I915_CONTEXT_PARAM_ENGINES` parameter and `struct
+ * i915_context_param_engines`.
+ *
+ * For such contexts the `I915_EXEC_RING_MASK` field becomes an index into the
+ * configured map.
+ *
+ * Example of creating such context and submitting against it:
+ *
+ * .. code-block:: C
+ *
+ * 	I915_DEFINE_CONTEXT_PARAM_ENGINES(engines, 2) = {
+ * 		.engines = { { I915_ENGINE_CLASS_RENDER, 0 },
+ * 			     { I915_ENGINE_CLASS_COPY, 0 } }
+ * 	};
+ * 	struct drm_i915_gem_context_create_ext_setparam p_engines = {
+ * 		.base = {
+ * 			.name = I915_CONTEXT_CREATE_EXT_SETPARAM,
+ * 		},
+ * 		.param = {
+ * 			.param = I915_CONTEXT_PARAM_ENGINES,
+ * 			.value = to_user_pointer(&engines),
+ * 			.size = sizeof(engines),
+ * 		},
+ * 	};
+ * 	struct drm_i915_gem_context_create_ext create = {
+ * 		.flags = I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS,
+ * 		.extensions = to_user_pointer(&p_engines);
+ * 	};
+ *
+ * 	ctx_id = gem_context_create_ext(drm_fd, &create);
+ *
+ * 	// We have now created a GEM context with two engines in the map:
+ * 	// Index 0 points to rcs0 while index 1 points to bcs0. Other engines
+ * 	// will not be accessible from this context.
+ *
+ * 	...
+ * 	execbuf.rsvd1 = ctx_id;
+ * 	execbuf.flags = 0; // Submits to index 0, which is rcs0 for this context
+ * 	gem_execbuf(drm_fd, &execbuf);
+ *
+ * 	...
+ * 	execbuf.rsvd1 = ctx_id;
+ * 	execbuf.flags = 1; // Submits to index 0, which is bcs0 for this context
+ * 	gem_execbuf(drm_fd, &execbuf);
+ */
+
+struct i915_context_param_engines {
+	__u64 extensions; /* linked chain of extension blocks, 0 terminates */
+#define I915_CONTEXT_ENGINES_EXT_LOAD_BALANCE 0 /* see i915_context_engines_load_balance */
+#define I915_CONTEXT_ENGINES_EXT_BOND 1 /* see i915_context_engines_bond */
+#define I915_CONTEXT_ENGINES_EXT_PARALLEL_SUBMIT 2 /* see i915_context_engines_parallel_submit */
+	struct i915_engine_class_instance engines[0];
+} __attribute__((packed));
+
+#define I915_DEFINE_CONTEXT_PARAM_ENGINES(name__, N__) struct { \
+	__u64 extensions; \
+	struct i915_engine_class_instance engines[N__]; \
+} __attribute__((packed)) name__
+
+/**
+ * struct drm_i915_gem_context_create_ext_setparam - Context parameter
+ * to set or query during context creation.
+ */
 struct drm_i915_gem_context_create_ext_setparam {
-#define I915_CONTEXT_CREATE_EXT_SETPARAM 0
+	/** @base: Extension link. See struct i915_user_extension. */
 	struct i915_user_extension base;
+
+	/**
+	 * @param: Context parameter to set or query.
+	 * See struct drm_i915_gem_context_param.
+	 */
 	struct drm_i915_gem_context_param param;
 };
 
@@ -1570,7 +2497,9 @@ struct drm_i915_gem_context_destroy {
 	__u32 pad;
 };
 
-/*
+/**
+ * struct drm_i915_gem_vm_control - Structure to create or destroy VM.
+ *
  * DRM_I915_GEM_VM_CREATE -
  *
  * Create a new virtual memory address space (ppGTT) for use within a context
@@ -1580,20 +2509,23 @@ struct drm_i915_gem_context_destroy {
  * The id of new VM (bound to the fd) for use with I915_CONTEXT_PARAM_VM is
  * returned in the outparam @id.
  *
- * No flags are defined, with all bits reserved and must be zero.
- *
  * An extension chain maybe provided, starting with @extensions, and terminated
  * by the @next_extension being 0. Currently, no extensions are defined.
  *
  * DRM_I915_GEM_VM_DESTROY -
  *
- * Destroys a previously created VM id, specified in @id.
+ * Destroys a previously created VM id, specified in @vm_id.
  *
  * No extensions or flags are allowed currently, and so must be zero.
  */
 struct drm_i915_gem_vm_control {
+	/** @extensions: Zero-terminated chain of extensions. */
 	__u64 extensions;
+
+	/** @flags: reserved for future usage, currently MBZ */
 	__u32 flags;
+
+	/** @vm_id: Id of the VM created or to be destroyed */
 	__u32 vm_id;
 };
 
@@ -1635,14 +2567,69 @@ struct drm_i915_reset_stats {
 	__u32 pad;
 };
 
+/**
+ * struct drm_i915_gem_userptr - Create GEM object from user allocated memory.
+ *
+ * Userptr objects have several restrictions on what ioctls can be used with the
+ * object handle.
+ */
 struct drm_i915_gem_userptr {
+	/**
+	 * @user_ptr: The pointer to the allocated memory.
+	 *
+	 * Needs to be aligned to PAGE_SIZE.
+	 */
 	__u64 user_ptr;
+
+	/**
+	 * @user_size:
+	 *
+	 * The size in bytes for the allocated memory. This will also become the
+	 * object size.
+	 *
+	 * Needs to be aligned to PAGE_SIZE, and should be at least PAGE_SIZE,
+	 * or larger.
+	 */
 	__u64 user_size;
+
+	/**
+	 * @flags:
+	 *
+	 * Supported flags:
+	 *
+	 * I915_USERPTR_READ_ONLY:
+	 *
+	 * Mark the object as readonly, this also means GPU access can only be
+	 * readonly. This is only supported on HW which supports readonly access
+	 * through the GTT. If the HW can't support readonly access, an error is
+	 * returned.
+	 *
+	 * I915_USERPTR_PROBE:
+	 *
+	 * Probe the provided @user_ptr range and validate that the @user_ptr is
+	 * indeed pointing to normal memory and that the range is also valid.
+	 * For example if some garbage address is given to the kernel, then this
+	 * should complain.
+	 *
+	 * Returns -EFAULT if the probe failed.
+	 *
+	 * Note that this doesn't populate the backing pages, and also doesn't
+	 * guarantee that the object will remain valid when the object is
+	 * eventually used.
+	 *
+	 * The kernel supports this feature if I915_PARAM_HAS_USERPTR_PROBE
+	 * returns a non-zero value.
+	 *
+	 * I915_USERPTR_UNSYNCHRONIZED:
+	 *
+	 * NOT USED. Setting this flag will result in an error.
+	 */
 	__u32 flags;
 #define I915_USERPTR_READ_ONLY 0x1
+#define I915_USERPTR_PROBE 0x2
 #define I915_USERPTR_UNSYNCHRONIZED 0x80000000
 	/**
-	 * Returned handle for the object.
+	 * @handle: Returned handle for the object.
 	 *
 	 * Object handles are nonzero.
 	 */
@@ -1671,23 +2658,31 @@ enum drm_i915_perf_property_id {
 	 * Open the stream for a specific context handle (as used with
 	 * execbuffer2). A stream opened for a specific context this way
 	 * won't typically require root privileges.
+	 *
+	 * This property is available in perf revision 1.
 	 */
 	DRM_I915_PERF_PROP_CTX_HANDLE = 1,
 
 	/**
 	 * A value of 1 requests the inclusion of raw OA unit reports as
 	 * part of stream samples.
+	 *
+	 * This property is available in perf revision 1.
 	 */
 	DRM_I915_PERF_PROP_SAMPLE_OA,
 
 	/**
 	 * The value specifies which set of OA unit metrics should be
-	 * be configured, defining the contents of any OA unit reports.
+	 * configured, defining the contents of any OA unit reports.
+	 *
+	 * This property is available in perf revision 1.
 	 */
 	DRM_I915_PERF_PROP_OA_METRICS_SET,
 
 	/**
 	 * The value specifies the size and layout of OA unit reports.
+	 *
+	 * This property is available in perf revision 1.
 	 */
 	DRM_I915_PERF_PROP_OA_FORMAT,
 
@@ -1697,9 +2692,46 @@ enum drm_i915_perf_property_id {
 	 * from this exponent as follows:
 	 *
 	 *   80ns * 2^(period_exponent + 1)
+	 *
+	 * This property is available in perf revision 1.
 	 */
 	DRM_I915_PERF_PROP_OA_EXPONENT,
 
+	/**
+	 * Specifying this property is only valid when specify a context to
+	 * filter with DRM_I915_PERF_PROP_CTX_HANDLE. Specifying this property
+	 * will hold preemption of the particular context we want to gather
+	 * performance data about. The execbuf2 submissions must include a
+	 * drm_i915_gem_execbuffer_ext_perf parameter for this to apply.
+	 *
+	 * This property is available in perf revision 3.
+	 */
+	DRM_I915_PERF_PROP_HOLD_PREEMPTION,
+
+	/**
+	 * Specifying this pins all contexts to the specified SSEU power
+	 * configuration for the duration of the recording.
+	 *
+	 * This parameter's value is a pointer to a struct
+	 * drm_i915_gem_context_param_sseu.
+	 *
+	 * This property is available in perf revision 4.
+	 */
+	DRM_I915_PERF_PROP_GLOBAL_SSEU,
+
+	/**
+	 * This optional parameter specifies the timer interval in nanoseconds
+	 * at which the i915 driver will check the OA buffer for available data.
+	 * Minimum allowed value is 100 microseconds. A default value is used by
+	 * the driver if this parameter is not specified. Note that larger timer
+	 * values will reduce cpu consumption during OA perf captures. However,
+	 * excessively large values would potentially result in OA buffer
+	 * overwrites as captures reach end of the OA buffer.
+	 *
+	 * This property is available in perf revision 5.
+	 */
+	DRM_I915_PERF_PROP_POLL_OA_PERIOD,
+
 	DRM_I915_PERF_PROP_MAX /* non-ABI */
 };
 
@@ -1719,7 +2751,7 @@ struct drm_i915_perf_open_param {
 	__u64 properties_ptr;
 };
 
-/**
+/*
  * Enable data capture for a stream that was either opened in a disabled state
  * via I915_PERF_FLAG_DISABLED or was later disabled via
  * I915_PERF_IOCTL_DISABLE.
@@ -1728,17 +2760,34 @@ struct drm_i915_perf_open_param {
  * to close and re-open a stream with the same configuration.
  *
  * It's undefined whether any pending data for the stream will be lost.
+ *
+ * This ioctl is available in perf revision 1.
  */
 #define I915_PERF_IOCTL_ENABLE	_IO('i', 0x0)
 
-/**
+/*
  * Disable data capture for a stream.
  *
  * It is an error to try and read a stream that is disabled.
+ *
+ * This ioctl is available in perf revision 1.
  */
 #define I915_PERF_IOCTL_DISABLE	_IO('i', 0x1)
 
-/**
+/*
+ * Change metrics_set captured by a stream.
+ *
+ * If the stream is bound to a specific context, the configuration change
+ * will performed __inline__ with that context such that it takes effect before
+ * the next execbuf submission.
+ *
+ * Returns the previously bound metrics set id, or a negative error code.
+ *
+ * This ioctl is available in perf revision 2.
+ */
+#define I915_PERF_IOCTL_CONFIG	_IO('i', 0x2)
+
+/*
  * Common to all i915 perf records
  */
 struct drm_i915_perf_record_header {
@@ -1787,127 +2836,887 @@ enum drm_i915_perf_record_type {
 };
 
 /**
+ * struct drm_i915_perf_oa_config
+ *
  * Structure to upload perf dynamic configuration into the kernel.
  */
 struct drm_i915_perf_oa_config {
-	/** String formatted like "%08x-%04x-%04x-%04x-%012x" */
+	/**
+	 * @uuid:
+	 *
+	 * String formatted like "%\08x-%\04x-%\04x-%\04x-%\012x"
+	 */
 	char uuid[36];
 
+	/**
+	 * @n_mux_regs:
+	 *
+	 * Number of mux regs in &mux_regs_ptr.
+	 */
 	__u32 n_mux_regs;
+
+	/**
+	 * @n_boolean_regs:
+	 *
+	 * Number of boolean regs in &boolean_regs_ptr.
+	 */
 	__u32 n_boolean_regs;
+
+	/**
+	 * @n_flex_regs:
+	 *
+	 * Number of flex regs in &flex_regs_ptr.
+	 */
 	__u32 n_flex_regs;
 
-	/*
-	 * These fields are pointers to tuples of u32 values (register address,
-	 * value). For example the expected length of the buffer pointed by
-	 * mux_regs_ptr is (2 * sizeof(u32) * n_mux_regs).
+	/**
+	 * @mux_regs_ptr:
+	 *
+	 * Pointer to tuples of u32 values (register address, value) for mux
+	 * registers.  Expected length of buffer is (2 * sizeof(u32) *
+	 * &n_mux_regs).
 	 */
 	__u64 mux_regs_ptr;
+
+	/**
+	 * @boolean_regs_ptr:
+	 *
+	 * Pointer to tuples of u32 values (register address, value) for mux
+	 * registers.  Expected length of buffer is (2 * sizeof(u32) *
+	 * &n_boolean_regs).
+	 */
 	__u64 boolean_regs_ptr;
+
+	/**
+	 * @flex_regs_ptr:
+	 *
+	 * Pointer to tuples of u32 values (register address, value) for mux
+	 * registers.  Expected length of buffer is (2 * sizeof(u32) *
+	 * &n_flex_regs).
+	 */
 	__u64 flex_regs_ptr;
 };
 
+/**
+ * struct drm_i915_query_item - An individual query for the kernel to process.
+ *
+ * The behaviour is determined by the @query_id. Note that exactly what
+ * @data_ptr is also depends on the specific @query_id.
+ */
 struct drm_i915_query_item {
+	/**
+	 * @query_id:
+	 *
+	 * The id for this query.  Currently accepted query IDs are:
+	 *  - %DRM_I915_QUERY_TOPOLOGY_INFO (see struct drm_i915_query_topology_info)
+	 *  - %DRM_I915_QUERY_ENGINE_INFO (see struct drm_i915_engine_info)
+	 *  - %DRM_I915_QUERY_PERF_CONFIG (see struct drm_i915_query_perf_config)
+	 *  - %DRM_I915_QUERY_MEMORY_REGIONS (see struct drm_i915_query_memory_regions)
+	 *  - %DRM_I915_QUERY_HWCONFIG_BLOB (see `GuC HWCONFIG blob uAPI`)
+	 *  - %DRM_I915_QUERY_GEOMETRY_SUBSLICES (see struct drm_i915_query_topology_info)
+	 */
 	__u64 query_id;
-#define DRM_I915_QUERY_TOPOLOGY_INFO    1
+#define DRM_I915_QUERY_TOPOLOGY_INFO		1
+#define DRM_I915_QUERY_ENGINE_INFO		2
+#define DRM_I915_QUERY_PERF_CONFIG		3
+#define DRM_I915_QUERY_MEMORY_REGIONS		4
+#define DRM_I915_QUERY_HWCONFIG_BLOB		5
+#define DRM_I915_QUERY_GEOMETRY_SUBSLICES	6
 /* Must be kept compact -- no holes and well documented */
 
-	/*
+	/**
+	 * @length:
+	 *
 	 * When set to zero by userspace, this is filled with the size of the
-	 * data to be written at the data_ptr pointer. The kernel sets this
+	 * data to be written at the @data_ptr pointer. The kernel sets this
 	 * value to a negative value to signal an error on a particular query
 	 * item.
 	 */
 	__s32 length;
 
-	/*
-	 * Unused for now. Must be cleared to zero.
+	/**
+	 * @flags:
+	 *
+	 * When &query_id == %DRM_I915_QUERY_TOPOLOGY_INFO, must be 0.
+	 *
+	 * When &query_id == %DRM_I915_QUERY_PERF_CONFIG, must be one of the
+	 * following:
+	 *
+	 *	- %DRM_I915_QUERY_PERF_CONFIG_LIST
+	 *      - %DRM_I915_QUERY_PERF_CONFIG_DATA_FOR_UUID
+	 *      - %DRM_I915_QUERY_PERF_CONFIG_FOR_UUID
+	 *
+	 * When &query_id == %DRM_I915_QUERY_GEOMETRY_SUBSLICES must contain
+	 * a struct i915_engine_class_instance that references a render engine.
 	 */
 	__u32 flags;
+#define DRM_I915_QUERY_PERF_CONFIG_LIST          1
+#define DRM_I915_QUERY_PERF_CONFIG_DATA_FOR_UUID 2
+#define DRM_I915_QUERY_PERF_CONFIG_DATA_FOR_ID   3
 
-	/*
-	 * Data will be written at the location pointed by data_ptr when the
-	 * value of length matches the length of the data to be written by the
+	/**
+	 * @data_ptr:
+	 *
+	 * Data will be written at the location pointed by @data_ptr when the
+	 * value of @length matches the length of the data to be written by the
 	 * kernel.
 	 */
 	__u64 data_ptr;
 };
 
+/**
+ * struct drm_i915_query - Supply an array of struct drm_i915_query_item for the
+ * kernel to fill out.
+ *
+ * Note that this is generally a two step process for each struct
+ * drm_i915_query_item in the array:
+ *
+ * 1. Call the DRM_IOCTL_I915_QUERY, giving it our array of struct
+ *    drm_i915_query_item, with &drm_i915_query_item.length set to zero. The
+ *    kernel will then fill in the size, in bytes, which tells userspace how
+ *    memory it needs to allocate for the blob(say for an array of properties).
+ *
+ * 2. Next we call DRM_IOCTL_I915_QUERY again, this time with the
+ *    &drm_i915_query_item.data_ptr equal to our newly allocated blob. Note that
+ *    the &drm_i915_query_item.length should still be the same as what the
+ *    kernel previously set. At this point the kernel can fill in the blob.
+ *
+ * Note that for some query items it can make sense for userspace to just pass
+ * in a buffer/blob equal to or larger than the required size. In this case only
+ * a single ioctl call is needed. For some smaller query items this can work
+ * quite well.
+ *
+ */
 struct drm_i915_query {
+	/** @num_items: The number of elements in the @items_ptr array */
 	__u32 num_items;
 
-	/*
-	 * Unused for now. Must be cleared to zero.
+	/**
+	 * @flags: Unused for now. Must be cleared to zero.
 	 */
 	__u32 flags;
 
-	/*
-	 * This points to an array of num_items drm_i915_query_item structures.
+	/**
+	 * @items_ptr:
+	 *
+	 * Pointer to an array of struct drm_i915_query_item. The number of
+	 * array elements is @num_items.
 	 */
 	__u64 items_ptr;
 };
 
-/*
- * Data written by the kernel with query DRM_I915_QUERY_TOPOLOGY_INFO :
- *
- * data: contains the 3 pieces of information :
- *
- * - the slice mask with one bit per slice telling whether a slice is
- *   available. The availability of slice X can be queried with the following
- *   formula :
- *
- *           (data[X / 8] >> (X % 8)) & 1
- *
- * - the subslice mask for each slice with one bit per subslice telling
- *   whether a subslice is available. The availability of subslice Y in slice
- *   X can be queried with the following formula :
- *
- *           (data[subslice_offset +
- *                 X * subslice_stride +
- *                 Y / 8] >> (Y % 8)) & 1
- *
- * - the EU mask for each subslice in each slice with one bit per EU telling
- *   whether an EU is available. The availability of EU Z in subslice Y in
- *   slice X can be queried with the following formula :
+/**
+ * struct drm_i915_query_topology_info
  *
- *           (data[eu_offset +
- *                 (X * max_subslices + Y) * eu_stride +
- *                 Z / 8] >> (Z % 8)) & 1
+ * Describes slice/subslice/EU information queried by
+ * %DRM_I915_QUERY_TOPOLOGY_INFO
  */
 struct drm_i915_query_topology_info {
-	/*
+	/**
+	 * @flags:
+	 *
 	 * Unused for now. Must be cleared to zero.
 	 */
 	__u16 flags;
 
+	/**
+	 * @max_slices:
+	 *
+	 * The number of bits used to express the slice mask.
+	 */
 	__u16 max_slices;
+
+	/**
+	 * @max_subslices:
+	 *
+	 * The number of bits used to express the subslice mask.
+	 */
 	__u16 max_subslices;
+
+	/**
+	 * @max_eus_per_subslice:
+	 *
+	 * The number of bits in the EU mask that correspond to a single
+	 * subslice's EUs.
+	 */
 	__u16 max_eus_per_subslice;
 
-	/*
+	/**
+	 * @subslice_offset:
+	 *
 	 * Offset in data[] at which the subslice masks are stored.
 	 */
 	__u16 subslice_offset;
 
-	/*
+	/**
+	 * @subslice_stride:
+	 *
 	 * Stride at which each of the subslice masks for each slice are
 	 * stored.
 	 */
 	__u16 subslice_stride;
 
-	/*
+	/**
+	 * @eu_offset:
+	 *
 	 * Offset in data[] at which the EU masks are stored.
 	 */
 	__u16 eu_offset;
 
-	/*
+	/**
+	 * @eu_stride:
+	 *
 	 * Stride at which each of the EU masks for each subslice are stored.
 	 */
 	__u16 eu_stride;
 
+	/**
+	 * @data:
+	 *
+	 * Contains 3 pieces of information :
+	 *
+	 * - The slice mask with one bit per slice telling whether a slice is
+	 *   available. The availability of slice X can be queried with the
+	 *   following formula :
+	 *
+	 *   .. code:: c
+	 *
+	 *      (data[X / 8] >> (X % 8)) & 1
+	 *
+	 *   Starting with Xe_HP platforms, Intel hardware no longer has
+	 *   traditional slices so i915 will always report a single slice
+	 *   (hardcoded slicemask = 0x1) which contains all of the platform's
+	 *   subslices.  I.e., the mask here does not reflect any of the newer
+	 *   hardware concepts such as "gslices" or "cslices" since userspace
+	 *   is capable of inferring those from the subslice mask.
+	 *
+	 * - The subslice mask for each slice with one bit per subslice telling
+	 *   whether a subslice is available.  Starting with Gen12 we use the
+	 *   term "subslice" to refer to what the hardware documentation
+	 *   describes as a "dual-subslices."  The availability of subslice Y
+	 *   in slice X can be queried with the following formula :
+	 *
+	 *   .. code:: c
+	 *
+	 *      (data[subslice_offset + X * subslice_stride + Y / 8] >> (Y % 8)) & 1
+	 *
+	 * - The EU mask for each subslice in each slice, with one bit per EU
+	 *   telling whether an EU is available. The availability of EU Z in
+	 *   subslice Y in slice X can be queried with the following formula :
+	 *
+	 *   .. code:: c
+	 *
+	 *      (data[eu_offset +
+	 *            (X * max_subslices + Y) * eu_stride +
+	 *            Z / 8
+	 *       ] >> (Z % 8)) & 1
+	 */
+	__u8 data[];
+};
+
+/**
+ * DOC: Engine Discovery uAPI
+ *
+ * Engine discovery uAPI is a way of enumerating physical engines present in a
+ * GPU associated with an open i915 DRM file descriptor. This supersedes the old
+ * way of using `DRM_IOCTL_I915_GETPARAM` and engine identifiers like
+ * `I915_PARAM_HAS_BLT`.
+ *
+ * The need for this interface came starting with Icelake and newer GPUs, which
+ * started to establish a pattern of having multiple engines of a same class,
+ * where not all instances were always completely functionally equivalent.
+ *
+ * Entry point for this uapi is `DRM_IOCTL_I915_QUERY` with the
+ * `DRM_I915_QUERY_ENGINE_INFO` as the queried item id.
+ *
+ * Example for getting the list of engines:
+ *
+ * .. code-block:: C
+ *
+ * 	struct drm_i915_query_engine_info *info;
+ * 	struct drm_i915_query_item item = {
+ * 		.query_id = DRM_I915_QUERY_ENGINE_INFO;
+ * 	};
+ * 	struct drm_i915_query query = {
+ * 		.num_items = 1,
+ * 		.items_ptr = (uintptr_t)&item,
+ * 	};
+ * 	int err, i;
+ *
+ * 	// First query the size of the blob we need, this needs to be large
+ * 	// enough to hold our array of engines. The kernel will fill out the
+ * 	// item.length for us, which is the number of bytes we need.
+ * 	//
+ * 	// Alternatively a large buffer can be allocated straight away enabling
+ * 	// querying in one pass, in which case item.length should contain the
+ * 	// length of the provided buffer.
+ * 	err = ioctl(fd, DRM_IOCTL_I915_QUERY, &query);
+ * 	if (err) ...
+ *
+ * 	info = calloc(1, item.length);
+ * 	// Now that we allocated the required number of bytes, we call the ioctl
+ * 	// again, this time with the data_ptr pointing to our newly allocated
+ * 	// blob, which the kernel can then populate with info on all engines.
+ * 	item.data_ptr = (uintptr_t)&info,
+ *
+ * 	err = ioctl(fd, DRM_IOCTL_I915_QUERY, &query);
+ * 	if (err) ...
+ *
+ * 	// We can now access each engine in the array
+ * 	for (i = 0; i < info->num_engines; i++) {
+ * 		struct drm_i915_engine_info einfo = info->engines[i];
+ * 		u16 class = einfo.engine.class;
+ * 		u16 instance = einfo.engine.instance;
+ * 		....
+ * 	}
+ *
+ * 	free(info);
+ *
+ * Each of the enumerated engines, apart from being defined by its class and
+ * instance (see `struct i915_engine_class_instance`), also can have flags and
+ * capabilities defined as documented in i915_drm.h.
+ *
+ * For instance video engines which support HEVC encoding will have the
+ * `I915_VIDEO_CLASS_CAPABILITY_HEVC` capability bit set.
+ *
+ * Engine discovery only fully comes to its own when combined with the new way
+ * of addressing engines when submitting batch buffers using contexts with
+ * engine maps configured.
+ */
+
+/**
+ * struct drm_i915_engine_info
+ *
+ * Describes one engine and it's capabilities as known to the driver.
+ */
+struct drm_i915_engine_info {
+	/** @engine: Engine class and instance. */
+	struct i915_engine_class_instance engine;
+
+	/** @rsvd0: Reserved field. */
+	__u32 rsvd0;
+
+	/** @flags: Engine flags. */
+	__u64 flags;
+#define I915_ENGINE_INFO_HAS_LOGICAL_INSTANCE		(1 << 0)
+
+	/** @capabilities: Capabilities of this engine. */
+	__u64 capabilities;
+#define I915_VIDEO_CLASS_CAPABILITY_HEVC		(1 << 0)
+#define I915_VIDEO_AND_ENHANCE_CLASS_CAPABILITY_SFC	(1 << 1)
+
+	/** @logical_instance: Logical instance of engine */
+	__u16 logical_instance;
+
+	/** @rsvd1: Reserved fields. */
+	__u16 rsvd1[3];
+	/** @rsvd2: Reserved fields. */
+	__u64 rsvd2[3];
+};
+
+/**
+ * struct drm_i915_query_engine_info
+ *
+ * Engine info query enumerates all engines known to the driver by filling in
+ * an array of struct drm_i915_engine_info structures.
+ */
+struct drm_i915_query_engine_info {
+	/** @num_engines: Number of struct drm_i915_engine_info structs following. */
+	__u32 num_engines;
+
+	/** @rsvd: MBZ */
+	__u32 rsvd[3];
+
+	/** @engines: Marker for drm_i915_engine_info structures. */
+	struct drm_i915_engine_info engines[];
+};
+
+/**
+ * struct drm_i915_query_perf_config
+ *
+ * Data written by the kernel with query %DRM_I915_QUERY_PERF_CONFIG and
+ * %DRM_I915_QUERY_GEOMETRY_SUBSLICES.
+ */
+struct drm_i915_query_perf_config {
+	union {
+		/**
+		 * @n_configs:
+		 *
+		 * When &drm_i915_query_item.flags ==
+		 * %DRM_I915_QUERY_PERF_CONFIG_LIST, i915 sets this fields to
+		 * the number of configurations available.
+		 */
+		__u64 n_configs;
+
+		/**
+		 * @config:
+		 *
+		 * When &drm_i915_query_item.flags ==
+		 * %DRM_I915_QUERY_PERF_CONFIG_DATA_FOR_ID, i915 will use the
+		 * value in this field as configuration identifier to decide
+		 * what data to write into config_ptr.
+		 */
+		__u64 config;
+
+		/**
+		 * @uuid:
+		 *
+		 * When &drm_i915_query_item.flags ==
+		 * %DRM_I915_QUERY_PERF_CONFIG_DATA_FOR_UUID, i915 will use the
+		 * value in this field as configuration identifier to decide
+		 * what data to write into config_ptr.
+		 *
+		 * String formatted like "%08x-%04x-%04x-%04x-%012x"
+		 */
+		char uuid[36];
+	};
+
+	/**
+	 * @flags:
+	 *
+	 * Unused for now. Must be cleared to zero.
+	 */
+	__u32 flags;
+
+	/**
+	 * @data:
+	 *
+	 * When &drm_i915_query_item.flags == %DRM_I915_QUERY_PERF_CONFIG_LIST,
+	 * i915 will write an array of __u64 of configuration identifiers.
+	 *
+	 * When &drm_i915_query_item.flags == %DRM_I915_QUERY_PERF_CONFIG_DATA,
+	 * i915 will write a struct drm_i915_perf_oa_config. If the following
+	 * fields of struct drm_i915_perf_oa_config are not set to 0, i915 will
+	 * write into the associated pointers the values of submitted when the
+	 * configuration was created :
+	 *
+	 *  - &drm_i915_perf_oa_config.n_mux_regs
+	 *  - &drm_i915_perf_oa_config.n_boolean_regs
+	 *  - &drm_i915_perf_oa_config.n_flex_regs
+	 */
 	__u8 data[];
 };
 
+/**
+ * enum drm_i915_gem_memory_class - Supported memory classes
+ */
+enum drm_i915_gem_memory_class {
+	/** @I915_MEMORY_CLASS_SYSTEM: System memory */
+	I915_MEMORY_CLASS_SYSTEM = 0,
+	/** @I915_MEMORY_CLASS_DEVICE: Device local-memory */
+	I915_MEMORY_CLASS_DEVICE,
+};
+
+/**
+ * struct drm_i915_gem_memory_class_instance - Identify particular memory region
+ */
+struct drm_i915_gem_memory_class_instance {
+	/** @memory_class: See enum drm_i915_gem_memory_class */
+	__u16 memory_class;
+
+	/** @memory_instance: Which instance */
+	__u16 memory_instance;
+};
+
+/**
+ * struct drm_i915_memory_region_info - Describes one region as known to the
+ * driver.
+ *
+ * Note this is using both struct drm_i915_query_item and struct drm_i915_query.
+ * For this new query we are adding the new query id DRM_I915_QUERY_MEMORY_REGIONS
+ * at &drm_i915_query_item.query_id.
+ */
+struct drm_i915_memory_region_info {
+	/** @region: The class:instance pair encoding */
+	struct drm_i915_gem_memory_class_instance region;
+
+	/** @rsvd0: MBZ */
+	__u32 rsvd0;
+
+	/**
+	 * @probed_size: Memory probed by the driver
+	 *
+	 * Note that it should not be possible to ever encounter a zero value
+	 * here, also note that no current region type will ever return -1 here.
+	 * Although for future region types, this might be a possibility. The
+	 * same applies to the other size fields.
+	 */
+	__u64 probed_size;
+
+	/**
+	 * @unallocated_size: Estimate of memory remaining
+	 *
+	 * Requires CAP_PERFMON or CAP_SYS_ADMIN to get reliable accounting.
+	 * Without this (or if this is an older kernel) the value here will
+	 * always equal the @probed_size. Note this is only currently tracked
+	 * for I915_MEMORY_CLASS_DEVICE regions (for other types the value here
+	 * will always equal the @probed_size).
+	 */
+	__u64 unallocated_size;
+
+	union {
+		/** @rsvd1: MBZ */
+		__u64 rsvd1[8];
+		struct {
+			/**
+			 * @probed_cpu_visible_size: Memory probed by the driver
+			 * that is CPU accessible.
+			 *
+			 * This will be always be <= @probed_size, and the
+			 * remainder (if there is any) will not be CPU
+			 * accessible.
+			 *
+			 * On systems without small BAR, the @probed_size will
+			 * always equal the @probed_cpu_visible_size, since all
+			 * of it will be CPU accessible.
+			 *
+			 * Note this is only tracked for
+			 * I915_MEMORY_CLASS_DEVICE regions (for other types the
+			 * value here will always equal the @probed_size).
+			 *
+			 * Note that if the value returned here is zero, then
+			 * this must be an old kernel which lacks the relevant
+			 * small-bar uAPI support (including
+			 * I915_GEM_CREATE_EXT_FLAG_NEEDS_CPU_ACCESS), but on
+			 * such systems we should never actually end up with a
+			 * small BAR configuration, assuming we are able to load
+			 * the kernel module. Hence it should be safe to treat
+			 * this the same as when @probed_cpu_visible_size ==
+			 * @probed_size.
+			 */
+			__u64 probed_cpu_visible_size;
+
+			/**
+			 * @unallocated_cpu_visible_size: Estimate of CPU
+			 * visible memory remaining.
+			 *
+			 * Note this is only tracked for
+			 * I915_MEMORY_CLASS_DEVICE regions (for other types the
+			 * value here will always equal the
+			 * @probed_cpu_visible_size).
+			 *
+			 * Requires CAP_PERFMON or CAP_SYS_ADMIN to get reliable
+			 * accounting.  Without this the value here will always
+			 * equal the @probed_cpu_visible_size. Note this is only
+			 * currently tracked for I915_MEMORY_CLASS_DEVICE
+			 * regions (for other types the value here will also
+			 * always equal the @probed_cpu_visible_size).
+			 *
+			 * If this is an older kernel the value here will be
+			 * zero, see also @probed_cpu_visible_size.
+			 */
+			__u64 unallocated_cpu_visible_size;
+		};
+	};
+};
+
+/**
+ * struct drm_i915_query_memory_regions
+ *
+ * The region info query enumerates all regions known to the driver by filling
+ * in an array of struct drm_i915_memory_region_info structures.
+ *
+ * Example for getting the list of supported regions:
+ *
+ * .. code-block:: C
+ *
+ *	struct drm_i915_query_memory_regions *info;
+ *	struct drm_i915_query_item item = {
+ *		.query_id = DRM_I915_QUERY_MEMORY_REGIONS;
+ *	};
+ *	struct drm_i915_query query = {
+ *		.num_items = 1,
+ *		.items_ptr = (uintptr_t)&item,
+ *	};
+ *	int err, i;
+ *
+ *	// First query the size of the blob we need, this needs to be large
+ *	// enough to hold our array of regions. The kernel will fill out the
+ *	// item.length for us, which is the number of bytes we need.
+ *	err = ioctl(fd, DRM_IOCTL_I915_QUERY, &query);
+ *	if (err) ...
+ *
+ *	info = calloc(1, item.length);
+ *	// Now that we allocated the required number of bytes, we call the ioctl
+ *	// again, this time with the data_ptr pointing to our newly allocated
+ *	// blob, which the kernel can then populate with the all the region info.
+ *	item.data_ptr = (uintptr_t)&info,
+ *
+ *	err = ioctl(fd, DRM_IOCTL_I915_QUERY, &query);
+ *	if (err) ...
+ *
+ *	// We can now access each region in the array
+ *	for (i = 0; i < info->num_regions; i++) {
+ *		struct drm_i915_memory_region_info mr = info->regions[i];
+ *		u16 class = mr.region.class;
+ *		u16 instance = mr.region.instance;
+ *
+ *		....
+ *	}
+ *
+ *	free(info);
+ */
+struct drm_i915_query_memory_regions {
+	/** @num_regions: Number of supported regions */
+	__u32 num_regions;
+
+	/** @rsvd: MBZ */
+	__u32 rsvd[3];
+
+	/** @regions: Info about each supported region */
+	struct drm_i915_memory_region_info regions[];
+};
+
+/**
+ * DOC: GuC HWCONFIG blob uAPI
+ *
+ * The GuC produces a blob with information about the current device.
+ * i915 reads this blob from GuC and makes it available via this uAPI.
+ *
+ * The format and meaning of the blob content are documented in the
+ * Programmer's Reference Manual.
+ */
+
+/**
+ * struct drm_i915_gem_create_ext - Existing gem_create behaviour, with added
+ * extension support using struct i915_user_extension.
+ *
+ * Note that new buffer flags should be added here, at least for the stuff that
+ * is immutable. Previously we would have two ioctls, one to create the object
+ * with gem_create, and another to apply various parameters, however this
+ * creates some ambiguity for the params which are considered immutable. Also in
+ * general we're phasing out the various SET/GET ioctls.
+ */
+struct drm_i915_gem_create_ext {
+	/**
+	 * @size: Requested size for the object.
+	 *
+	 * The (page-aligned) allocated size for the object will be returned.
+	 *
+	 * DG2 64K min page size implications:
+	 *
+	 * On discrete platforms, starting from DG2, we have to contend with GTT
+	 * page size restrictions when dealing with I915_MEMORY_CLASS_DEVICE
+	 * objects.  Specifically the hardware only supports 64K or larger GTT
+	 * page sizes for such memory. The kernel will already ensure that all
+	 * I915_MEMORY_CLASS_DEVICE memory is allocated using 64K or larger page
+	 * sizes underneath.
+	 *
+	 * Note that the returned size here will always reflect any required
+	 * rounding up done by the kernel, i.e 4K will now become 64K on devices
+	 * such as DG2. The kernel will always select the largest minimum
+	 * page-size for the set of possible placements as the value to use when
+	 * rounding up the @size.
+	 *
+	 * Special DG2 GTT address alignment requirement:
+	 *
+	 * The GTT alignment will also need to be at least 2M for such objects.
+	 *
+	 * Note that due to how the hardware implements 64K GTT page support, we
+	 * have some further complications:
+	 *
+	 *   1) The entire PDE (which covers a 2MB virtual address range), must
+	 *   contain only 64K PTEs, i.e mixing 4K and 64K PTEs in the same
+	 *   PDE is forbidden by the hardware.
+	 *
+	 *   2) We still need to support 4K PTEs for I915_MEMORY_CLASS_SYSTEM
+	 *   objects.
+	 *
+	 * To keep things simple for userland, we mandate that any GTT mappings
+	 * must be aligned to and rounded up to 2MB. The kernel will internally
+	 * pad them out to the next 2MB boundary. As this only wastes virtual
+	 * address space and avoids userland having to copy any needlessly
+	 * complicated PDE sharing scheme (coloring) and only affects DG2, this
+	 * is deemed to be a good compromise.
+	 */
+	__u64 size;
+
+	/**
+	 * @handle: Returned handle for the object.
+	 *
+	 * Object handles are nonzero.
+	 */
+	__u32 handle;
+
+	/**
+	 * @flags: Optional flags.
+	 *
+	 * Supported values:
+	 *
+	 * I915_GEM_CREATE_EXT_FLAG_NEEDS_CPU_ACCESS - Signal to the kernel that
+	 * the object will need to be accessed via the CPU.
+	 *
+	 * Only valid when placing objects in I915_MEMORY_CLASS_DEVICE, and only
+	 * strictly required on configurations where some subset of the device
+	 * memory is directly visible/mappable through the CPU (which we also
+	 * call small BAR), like on some DG2+ systems. Note that this is quite
+	 * undesirable, but due to various factors like the client CPU, BIOS etc
+	 * it's something we can expect to see in the wild. See
+	 * &drm_i915_memory_region_info.probed_cpu_visible_size for how to
+	 * determine if this system applies.
+	 *
+	 * Note that one of the placements MUST be I915_MEMORY_CLASS_SYSTEM, to
+	 * ensure the kernel can always spill the allocation to system memory,
+	 * if the object can't be allocated in the mappable part of
+	 * I915_MEMORY_CLASS_DEVICE.
+	 *
+	 * Also note that since the kernel only supports flat-CCS on objects
+	 * that can *only* be placed in I915_MEMORY_CLASS_DEVICE, we therefore
+	 * don't support I915_GEM_CREATE_EXT_FLAG_NEEDS_CPU_ACCESS together with
+	 * flat-CCS.
+	 *
+	 * Without this hint, the kernel will assume that non-mappable
+	 * I915_MEMORY_CLASS_DEVICE is preferred for this object. Note that the
+	 * kernel can still migrate the object to the mappable part, as a last
+	 * resort, if userspace ever CPU faults this object, but this might be
+	 * expensive, and so ideally should be avoided.
+	 *
+	 * On older kernels which lack the relevant small-bar uAPI support (see
+	 * also &drm_i915_memory_region_info.probed_cpu_visible_size),
+	 * usage of the flag will result in an error, but it should NEVER be
+	 * possible to end up with a small BAR configuration, assuming we can
+	 * also successfully load the i915 kernel module. In such cases the
+	 * entire I915_MEMORY_CLASS_DEVICE region will be CPU accessible, and as
+	 * such there are zero restrictions on where the object can be placed.
+	 */
+#define I915_GEM_CREATE_EXT_FLAG_NEEDS_CPU_ACCESS (1 << 0)
+	__u32 flags;
+
+	/**
+	 * @extensions: The chain of extensions to apply to this object.
+	 *
+	 * This will be useful in the future when we need to support several
+	 * different extensions, and we need to apply more than one when
+	 * creating the object. See struct i915_user_extension.
+	 *
+	 * If we don't supply any extensions then we get the same old gem_create
+	 * behaviour.
+	 *
+	 * For I915_GEM_CREATE_EXT_MEMORY_REGIONS usage see
+	 * struct drm_i915_gem_create_ext_memory_regions.
+	 *
+	 * For I915_GEM_CREATE_EXT_PROTECTED_CONTENT usage see
+	 * struct drm_i915_gem_create_ext_protected_content.
+	 */
+#define I915_GEM_CREATE_EXT_MEMORY_REGIONS 0
+#define I915_GEM_CREATE_EXT_PROTECTED_CONTENT 1
+	__u64 extensions;
+};
+
+/**
+ * struct drm_i915_gem_create_ext_memory_regions - The
+ * I915_GEM_CREATE_EXT_MEMORY_REGIONS extension.
+ *
+ * Set the object with the desired set of placements/regions in priority
+ * order. Each entry must be unique and supported by the device.
+ *
+ * This is provided as an array of struct drm_i915_gem_memory_class_instance, or
+ * an equivalent layout of class:instance pair encodings. See struct
+ * drm_i915_query_memory_regions and DRM_I915_QUERY_MEMORY_REGIONS for how to
+ * query the supported regions for a device.
+ *
+ * As an example, on discrete devices, if we wish to set the placement as
+ * device local-memory we can do something like:
+ *
+ * .. code-block:: C
+ *
+ *	struct drm_i915_gem_memory_class_instance region_lmem = {
+ *              .memory_class = I915_MEMORY_CLASS_DEVICE,
+ *              .memory_instance = 0,
+ *      };
+ *      struct drm_i915_gem_create_ext_memory_regions regions = {
+ *              .base = { .name = I915_GEM_CREATE_EXT_MEMORY_REGIONS },
+ *              .regions = (uintptr_t)&region_lmem,
+ *              .num_regions = 1,
+ *      };
+ *      struct drm_i915_gem_create_ext create_ext = {
+ *              .size = 16 * PAGE_SIZE,
+ *              .extensions = (uintptr_t)&regions,
+ *      };
+ *
+ *      int err = ioctl(fd, DRM_IOCTL_I915_GEM_CREATE_EXT, &create_ext);
+ *      if (err) ...
+ *
+ * At which point we get the object handle in &drm_i915_gem_create_ext.handle,
+ * along with the final object size in &drm_i915_gem_create_ext.size, which
+ * should account for any rounding up, if required.
+ *
+ * Note that userspace has no means of knowing the current backing region
+ * for objects where @num_regions is larger than one. The kernel will only
+ * ensure that the priority order of the @regions array is honoured, either
+ * when initially placing the object, or when moving memory around due to
+ * memory pressure
+ *
+ * On Flat-CCS capable HW, compression is supported for the objects residing
+ * in I915_MEMORY_CLASS_DEVICE. When such objects (compressed) have other
+ * memory class in @regions and migrated (by i915, due to memory
+ * constraints) to the non I915_MEMORY_CLASS_DEVICE region, then i915 needs to
+ * decompress the content. But i915 doesn't have the required information to
+ * decompress the userspace compressed objects.
+ *
+ * So i915 supports Flat-CCS, on the objects which can reside only on
+ * I915_MEMORY_CLASS_DEVICE regions.
+ */
+struct drm_i915_gem_create_ext_memory_regions {
+	/** @base: Extension link. See struct i915_user_extension. */
+	struct i915_user_extension base;
+
+	/** @pad: MBZ */
+	__u32 pad;
+	/** @num_regions: Number of elements in the @regions array. */
+	__u32 num_regions;
+	/**
+	 * @regions: The regions/placements array.
+	 *
+	 * An array of struct drm_i915_gem_memory_class_instance.
+	 */
+	__u64 regions;
+};
+
+/**
+ * struct drm_i915_gem_create_ext_protected_content - The
+ * I915_OBJECT_PARAM_PROTECTED_CONTENT extension.
+ *
+ * If this extension is provided, buffer contents are expected to be protected
+ * by PXP encryption and require decryption for scan out and processing. This
+ * is only possible on platforms that have PXP enabled, on all other scenarios
+ * using this extension will cause the ioctl to fail and return -ENODEV. The
+ * flags parameter is reserved for future expansion and must currently be set
+ * to zero.
+ *
+ * The buffer contents are considered invalid after a PXP session teardown.
+ *
+ * The encryption is guaranteed to be processed correctly only if the object
+ * is submitted with a context created using the
+ * I915_CONTEXT_PARAM_PROTECTED_CONTENT flag. This will also enable extra checks
+ * at submission time on the validity of the objects involved.
+ *
+ * Below is an example on how to create a protected object:
+ *
+ * .. code-block:: C
+ *
+ *      struct drm_i915_gem_create_ext_protected_content protected_ext = {
+ *              .base = { .name = I915_GEM_CREATE_EXT_PROTECTED_CONTENT },
+ *              .flags = 0,
+ *      };
+ *      struct drm_i915_gem_create_ext create_ext = {
+ *              .size = PAGE_SIZE,
+ *              .extensions = (uintptr_t)&protected_ext,
+ *      };
+ *
+ *      int err = ioctl(fd, DRM_IOCTL_I915_GEM_CREATE_EXT, &create_ext);
+ *      if (err) ...
+ */
+struct drm_i915_gem_create_ext_protected_content {
+	/** @base: Extension link. See struct i915_user_extension. */
+	struct i915_user_extension base;
+	/** @flags: reserved for future usage, currently MBZ */
+	__u32 flags;
+};
+
+/* ID of the protected content session managed by i915 when PXP is active */
+#define I915_PROTECTED_CONTENT_DEFAULT_SESSION 0xf
+
 #if defined(__cplusplus)
 }
 #endif
diff --git a/include/drm/tegra_drm.h b/include/drm/tegra_drm.h
index 6c07919c..94cfc306 100644
--- a/include/drm/tegra_drm.h
+++ b/include/drm/tegra_drm.h
@@ -1,27 +1,8 @@
-/*
- * Copyright (c) 2012-2013, NVIDIA CORPORATION.  All rights reserved.
- *
- * Permission is hereby granted, free of charge, to any person obtaining a
- * copy of this software and associated documentation files (the "Software"),
- * to deal in the Software without restriction, including without limitation
- * the rights to use, copy, modify, merge, publish, distribute, sublicense,
- * and/or sell copies of the Software, and to permit persons to whom the
- * Software is furnished to do so, subject to the following conditions:
- *
- * The above copyright notice and this permission notice shall be included in
- * all copies or substantial portions of the Software.
- *
- * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
- * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
- * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
- * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
- * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
- * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
- * OTHER DEALINGS IN THE SOFTWARE.
- */
+/* SPDX-License-Identifier: MIT */
+/* Copyright (c) 2012-2020 NVIDIA Corporation */
 
-#ifndef _TEGRA_DRM_H_
-#define _TEGRA_DRM_H_
+#ifndef _UAPI_TEGRA_DRM_H_
+#define _UAPI_TEGRA_DRM_H_
 
 #include "drm.h"
 
@@ -29,6 +10,8 @@
 extern "C" {
 #endif
 
+/* Tegra DRM legacy UAPI. Only enabled with STAGING */
+
 #define DRM_TEGRA_GEM_CREATE_TILED     (1 << 0)
 #define DRM_TEGRA_GEM_CREATE_BOTTOM_UP (1 << 1)
 
@@ -649,8 +632,8 @@ struct drm_tegra_gem_get_flags {
 #define DRM_TEGRA_SYNCPT_READ		0x02
 #define DRM_TEGRA_SYNCPT_INCR		0x03
 #define DRM_TEGRA_SYNCPT_WAIT		0x04
-#define DRM_TEGRA_OPEN_CHANNEL		0x05
-#define DRM_TEGRA_CLOSE_CHANNEL		0x06
+#define DRM_TEGRA_OPEN_CHANNEL	        0x05
+#define DRM_TEGRA_CLOSE_CHANNEL	        0x06
 #define DRM_TEGRA_GET_SYNCPT		0x07
 #define DRM_TEGRA_SUBMIT		0x08
 #define DRM_TEGRA_GET_SYNCPT_BASE	0x09
@@ -674,6 +657,402 @@ struct drm_tegra_gem_get_flags {
 #define DRM_IOCTL_TEGRA_GEM_SET_FLAGS DRM_IOWR(DRM_COMMAND_BASE + DRM_TEGRA_GEM_SET_FLAGS, struct drm_tegra_gem_set_flags)
 #define DRM_IOCTL_TEGRA_GEM_GET_FLAGS DRM_IOWR(DRM_COMMAND_BASE + DRM_TEGRA_GEM_GET_FLAGS, struct drm_tegra_gem_get_flags)
 
+/* New Tegra DRM UAPI */
+
+/*
+ * Reported by the driver in the `capabilities` field.
+ *
+ * DRM_TEGRA_CHANNEL_CAP_CACHE_COHERENT: If set, the engine is cache coherent
+ * with regard to the system memory.
+ */
+#define DRM_TEGRA_CHANNEL_CAP_CACHE_COHERENT (1 << 0)
+
+struct drm_tegra_channel_open {
+	/**
+	 * @host1x_class: [in]
+	 *
+	 * Host1x class of the engine that will be programmed using this
+	 * channel.
+	 */
+	__u32 host1x_class;
+
+	/**
+	 * @flags: [in]
+	 *
+	 * Flags.
+	 */
+	__u32 flags;
+
+	/**
+	 * @context: [out]
+	 *
+	 * Opaque identifier corresponding to the opened channel.
+	 */
+	__u32 context;
+
+	/**
+	 * @version: [out]
+	 *
+	 * Version of the engine hardware. This can be used by userspace
+	 * to determine how the engine needs to be programmed.
+	 */
+	__u32 version;
+
+	/**
+	 * @capabilities: [out]
+	 *
+	 * Flags describing the hardware capabilities.
+	 */
+	__u32 capabilities;
+	__u32 padding;
+};
+
+struct drm_tegra_channel_close {
+	/**
+	 * @context: [in]
+	 *
+	 * Identifier of the channel to close.
+	 */
+	__u32 context;
+	__u32 padding;
+};
+
+/*
+ * Mapping flags that can be used to influence how the mapping is created.
+ *
+ * DRM_TEGRA_CHANNEL_MAP_READ: create mapping that allows HW read access
+ * DRM_TEGRA_CHANNEL_MAP_WRITE: create mapping that allows HW write access
+ */
+#define DRM_TEGRA_CHANNEL_MAP_READ  (1 << 0)
+#define DRM_TEGRA_CHANNEL_MAP_WRITE (1 << 1)
+#define DRM_TEGRA_CHANNEL_MAP_READ_WRITE (DRM_TEGRA_CHANNEL_MAP_READ | \
+					  DRM_TEGRA_CHANNEL_MAP_WRITE)
+
+struct drm_tegra_channel_map {
+	/**
+	 * @context: [in]
+	 *
+	 * Identifier of the channel to which make memory available for.
+	 */
+	__u32 context;
+
+	/**
+	 * @handle: [in]
+	 *
+	 * GEM handle of the memory to map.
+	 */
+	__u32 handle;
+
+	/**
+	 * @flags: [in]
+	 *
+	 * Flags.
+	 */
+	__u32 flags;
+
+	/**
+	 * @mapping: [out]
+	 *
+	 * Identifier corresponding to the mapping, to be used for
+	 * relocations or unmapping later.
+	 */
+	__u32 mapping;
+};
+
+struct drm_tegra_channel_unmap {
+	/**
+	 * @context: [in]
+	 *
+	 * Channel identifier of the channel to unmap memory from.
+	 */
+	__u32 context;
+
+	/**
+	 * @mapping: [in]
+	 *
+	 * Mapping identifier of the memory mapping to unmap.
+	 */
+	__u32 mapping;
+};
+
+/* Submission */
+
+/**
+ * Specify that bit 39 of the patched-in address should be set to switch
+ * swizzling between Tegra and non-Tegra sector layout on systems that store
+ * surfaces in system memory in non-Tegra sector layout.
+ */
+#define DRM_TEGRA_SUBMIT_RELOC_SECTOR_LAYOUT (1 << 0)
+
+struct drm_tegra_submit_buf {
+	/**
+	 * @mapping: [in]
+	 *
+	 * Identifier of the mapping to use in the submission.
+	 */
+	__u32 mapping;
+
+	/**
+	 * @flags: [in]
+	 *
+	 * Flags.
+	 */
+	__u32 flags;
+
+	/**
+	 * Information for relocation patching.
+	 */
+	struct {
+		/**
+		 * @target_offset: [in]
+		 *
+		 * Offset from the start of the mapping of the data whose
+		 * address is to be patched into the gather.
+		 */
+		__u64 target_offset;
+
+		/**
+		 * @gather_offset_words: [in]
+		 *
+		 * Offset in words from the start of the gather data to
+		 * where the address should be patched into.
+		 */
+		__u32 gather_offset_words;
+
+		/**
+		 * @shift: [in]
+		 *
+		 * Number of bits the address should be shifted right before
+		 * patching in.
+		 */
+		__u32 shift;
+	} reloc;
+};
+
+/**
+ * Execute `words` words of Host1x opcodes specified in the `gather_data_ptr`
+ * buffer. Each GATHER_UPTR command uses successive words from the buffer.
+ */
+#define DRM_TEGRA_SUBMIT_CMD_GATHER_UPTR		0
+/**
+ * Wait for a syncpoint to reach a value before continuing with further
+ * commands.
+ */
+#define DRM_TEGRA_SUBMIT_CMD_WAIT_SYNCPT		1
+/**
+ * Wait for a syncpoint to reach a value before continuing with further
+ * commands. The threshold is calculated relative to the start of the job.
+ */
+#define DRM_TEGRA_SUBMIT_CMD_WAIT_SYNCPT_RELATIVE	2
+
+struct drm_tegra_submit_cmd_gather_uptr {
+	__u32 words;
+	__u32 reserved[3];
+};
+
+struct drm_tegra_submit_cmd_wait_syncpt {
+	__u32 id;
+	__u32 value;
+	__u32 reserved[2];
+};
+
+struct drm_tegra_submit_cmd {
+	/**
+	 * @type: [in]
+	 *
+	 * Command type to execute. One of the DRM_TEGRA_SUBMIT_CMD*
+	 * defines.
+	 */
+	__u32 type;
+
+	/**
+	 * @flags: [in]
+	 *
+	 * Flags.
+	 */
+	__u32 flags;
+
+	union {
+		struct drm_tegra_submit_cmd_gather_uptr gather_uptr;
+		struct drm_tegra_submit_cmd_wait_syncpt wait_syncpt;
+		__u32 reserved[4];
+	};
+};
+
+struct drm_tegra_submit_syncpt {
+	/**
+	 * @id: [in]
+	 *
+	 * ID of the syncpoint that the job will increment.
+	 */
+	__u32 id;
+
+	/**
+	 * @flags: [in]
+	 *
+	 * Flags.
+	 */
+	__u32 flags;
+
+	/**
+	 * @increments: [in]
+	 *
+	 * Number of times the job will increment this syncpoint.
+	 */
+	__u32 increments;
+
+	/**
+	 * @value: [out]
+	 *
+	 * Value the syncpoint will have once the job has completed all
+	 * its specified syncpoint increments.
+	 *
+	 * Note that the kernel may increment the syncpoint before or after
+	 * the job. These increments are not reflected in this field.
+	 *
+	 * If the job hangs or times out, not all of the increments may
+	 * get executed.
+	 */
+	__u32 value;
+};
+
+struct drm_tegra_channel_submit {
+	/**
+	 * @context: [in]
+	 *
+	 * Identifier of the channel to submit this job to.
+	 */
+	__u32 context;
+
+	/**
+	 * @num_bufs: [in]
+	 *
+	 * Number of elements in the `bufs_ptr` array.
+	 */
+	__u32 num_bufs;
+
+	/**
+	 * @num_cmds: [in]
+	 *
+	 * Number of elements in the `cmds_ptr` array.
+	 */
+	__u32 num_cmds;
+
+	/**
+	 * @gather_data_words: [in]
+	 *
+	 * Number of 32-bit words in the `gather_data_ptr` array.
+	 */
+	__u32 gather_data_words;
+
+	/**
+	 * @bufs_ptr: [in]
+	 *
+	 * Pointer to an array of drm_tegra_submit_buf structures.
+	 */
+	__u64 bufs_ptr;
+
+	/**
+	 * @cmds_ptr: [in]
+	 *
+	 * Pointer to an array of drm_tegra_submit_cmd structures.
+	 */
+	__u64 cmds_ptr;
+
+	/**
+	 * @gather_data_ptr: [in]
+	 *
+	 * Pointer to an array of Host1x opcodes to be used by GATHER_UPTR
+	 * commands.
+	 */
+	__u64 gather_data_ptr;
+
+	/**
+	 * @syncobj_in: [in]
+	 *
+	 * Handle for DRM syncobj that will be waited before submission.
+	 * Ignored if zero.
+	 */
+	__u32 syncobj_in;
+
+	/**
+	 * @syncobj_out: [in]
+	 *
+	 * Handle for DRM syncobj that will have its fence replaced with
+	 * the job's completion fence. Ignored if zero.
+	 */
+	__u32 syncobj_out;
+
+	/**
+	 * @syncpt_incr: [in,out]
+	 *
+	 * Information about the syncpoint the job will increment.
+	 */
+	struct drm_tegra_submit_syncpt syncpt;
+};
+
+struct drm_tegra_syncpoint_allocate {
+	/**
+	 * @id: [out]
+	 *
+	 * ID of allocated syncpoint.
+	 */
+	__u32 id;
+	__u32 padding;
+};
+
+struct drm_tegra_syncpoint_free {
+	/**
+	 * @id: [in]
+	 *
+	 * ID of syncpoint to free.
+	 */
+	__u32 id;
+	__u32 padding;
+};
+
+struct drm_tegra_syncpoint_wait {
+	/**
+	 * @timeout: [in]
+	 *
+	 * Absolute timestamp at which the wait will time out.
+	 */
+	__s64 timeout_ns;
+
+	/**
+	 * @id: [in]
+	 *
+	 * ID of syncpoint to wait on.
+	 */
+	__u32 id;
+
+	/**
+	 * @threshold: [in]
+	 *
+	 * Threshold to wait for.
+	 */
+	__u32 threshold;
+
+	/**
+	 * @value: [out]
+	 *
+	 * Value of the syncpoint upon wait completion.
+	 */
+	__u32 value;
+
+	__u32 padding;
+};
+
+#define DRM_IOCTL_TEGRA_CHANNEL_OPEN DRM_IOWR(DRM_COMMAND_BASE + 0x10, struct drm_tegra_channel_open)
+#define DRM_IOCTL_TEGRA_CHANNEL_CLOSE DRM_IOWR(DRM_COMMAND_BASE + 0x11, struct drm_tegra_channel_close)
+#define DRM_IOCTL_TEGRA_CHANNEL_MAP DRM_IOWR(DRM_COMMAND_BASE + 0x12, struct drm_tegra_channel_map)
+#define DRM_IOCTL_TEGRA_CHANNEL_UNMAP DRM_IOWR(DRM_COMMAND_BASE + 0x13, struct drm_tegra_channel_unmap)
+#define DRM_IOCTL_TEGRA_CHANNEL_SUBMIT DRM_IOWR(DRM_COMMAND_BASE + 0x14, struct drm_tegra_channel_submit)
+
+#define DRM_IOCTL_TEGRA_SYNCPOINT_ALLOCATE DRM_IOWR(DRM_COMMAND_BASE + 0x20, struct drm_tegra_syncpoint_allocate)
+#define DRM_IOCTL_TEGRA_SYNCPOINT_FREE DRM_IOWR(DRM_COMMAND_BASE + 0x21, struct drm_tegra_syncpoint_free)
+#define DRM_IOCTL_TEGRA_SYNCPOINT_WAIT DRM_IOWR(DRM_COMMAND_BASE + 0x22, struct drm_tegra_syncpoint_wait)
+
 #if defined(__cplusplus)
 }
 #endif
diff --git a/intel/Android.sources.bp b/intel/Android.sources.bp
index 46e0328f..459c070f 100644
--- a/intel/Android.sources.bp
+++ b/intel/Android.sources.bp
@@ -7,7 +7,6 @@ cc_defaults {
         "intel_bufmgr_fake.c",
         "intel_bufmgr_gem.c",
         "intel_decode.c",
-        "intel_chipset.c",
         "mm.c",
     ],
 }
diff --git a/intel/Makefile.sources b/intel/Makefile.sources
deleted file mode 100644
index aa27e273..00000000
--- a/intel/Makefile.sources
+++ /dev/null
@@ -1,17 +0,0 @@
-LIBDRM_INTEL_FILES := \
-	i915_pciids.h \
-	intel_bufmgr.c \
-	intel_bufmgr_priv.h \
-	intel_bufmgr_fake.c \
-	intel_bufmgr_gem.c \
-	intel_decode.c \
-	intel_chipset.h \
-	intel_chipset.c \
-	mm.c \
-	mm.h \
-	uthash.h
-
-LIBDRM_INTEL_H_FILES := \
-	intel_bufmgr.h \
-	intel_aub.h \
-	intel_debug.h
diff --git a/intel/i915_pciids.h b/intel/i915_pciids.h
deleted file mode 100644
index 8076d40c..00000000
--- a/intel/i915_pciids.h
+++ /dev/null
@@ -1,684 +0,0 @@
-/*
- * Copyright 2013 Intel Corporation
- * All Rights Reserved.
- *
- * Permission is hereby granted, free of charge, to any person obtaining a
- * copy of this software and associated documentation files (the
- * "Software"), to deal in the Software without restriction, including
- * without limitation the rights to use, copy, modify, merge, publish,
- * distribute, sub license, and/or sell copies of the Software, and to
- * permit persons to whom the Software is furnished to do so, subject to
- * the following conditions:
- *
- * The above copyright notice and this permission notice (including the
- * next paragraph) shall be included in all copies or substantial portions
- * of the Software.
- *
- * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
- * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
- * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
- * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
- * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
- * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
- * DEALINGS IN THE SOFTWARE.
- */
-#ifndef _I915_PCIIDS_H
-#define _I915_PCIIDS_H
-
-/*
- * A pci_device_id struct {
- *	__u32 vendor, device;
- *      __u32 subvendor, subdevice;
- *	__u32 class, class_mask;
- *	kernel_ulong_t driver_data;
- * };
- * Don't use C99 here because "class" is reserved and we want to
- * give userspace flexibility.
- */
-#define INTEL_VGA_DEVICE(id, info) {		\
-	0x8086,	id,				\
-	~0, ~0,					\
-	0x030000, 0xff0000,			\
-	(unsigned long) info }
-
-#define INTEL_QUANTA_VGA_DEVICE(info) {		\
-	0x8086,	0x16a,				\
-	0x152d,	0x8990,				\
-	0x030000, 0xff0000,			\
-	(unsigned long) info }
-
-#define INTEL_I810_IDS(info)					\
-	INTEL_VGA_DEVICE(0x7121, info), /* I810 */		\
-	INTEL_VGA_DEVICE(0x7123, info), /* I810_DC100 */	\
-	INTEL_VGA_DEVICE(0x7125, info)  /* I810_E */
-
-#define INTEL_I815_IDS(info)					\
-	INTEL_VGA_DEVICE(0x1132, info)  /* I815*/
-
-#define INTEL_I830_IDS(info)				\
-	INTEL_VGA_DEVICE(0x3577, info)
-
-#define INTEL_I845G_IDS(info)				\
-	INTEL_VGA_DEVICE(0x2562, info)
-
-#define INTEL_I85X_IDS(info)				\
-	INTEL_VGA_DEVICE(0x3582, info), /* I855_GM */ \
-	INTEL_VGA_DEVICE(0x358e, info)
-
-#define INTEL_I865G_IDS(info)				\
-	INTEL_VGA_DEVICE(0x2572, info) /* I865_G */
-
-#define INTEL_I915G_IDS(info)				\
-	INTEL_VGA_DEVICE(0x2582, info), /* I915_G */ \
-	INTEL_VGA_DEVICE(0x258a, info)  /* E7221_G */
-
-#define INTEL_I915GM_IDS(info)				\
-	INTEL_VGA_DEVICE(0x2592, info) /* I915_GM */
-
-#define INTEL_I945G_IDS(info)				\
-	INTEL_VGA_DEVICE(0x2772, info) /* I945_G */
-
-#define INTEL_I945GM_IDS(info)				\
-	INTEL_VGA_DEVICE(0x27a2, info), /* I945_GM */ \
-	INTEL_VGA_DEVICE(0x27ae, info)  /* I945_GME */
-
-#define INTEL_I965G_IDS(info)				\
-	INTEL_VGA_DEVICE(0x2972, info), /* I946_GZ */	\
-	INTEL_VGA_DEVICE(0x2982, info),	/* G35_G */	\
-	INTEL_VGA_DEVICE(0x2992, info),	/* I965_Q */	\
-	INTEL_VGA_DEVICE(0x29a2, info)	/* I965_G */
-
-#define INTEL_G33_IDS(info)				\
-	INTEL_VGA_DEVICE(0x29b2, info), /* Q35_G */ \
-	INTEL_VGA_DEVICE(0x29c2, info),	/* G33_G */ \
-	INTEL_VGA_DEVICE(0x29d2, info)	/* Q33_G */
-
-#define INTEL_I965GM_IDS(info)				\
-	INTEL_VGA_DEVICE(0x2a02, info),	/* I965_GM */ \
-	INTEL_VGA_DEVICE(0x2a12, info)  /* I965_GME */
-
-#define INTEL_GM45_IDS(info)				\
-	INTEL_VGA_DEVICE(0x2a42, info) /* GM45_G */
-
-#define INTEL_G45_IDS(info)				\
-	INTEL_VGA_DEVICE(0x2e02, info), /* IGD_E_G */ \
-	INTEL_VGA_DEVICE(0x2e12, info), /* Q45_G */ \
-	INTEL_VGA_DEVICE(0x2e22, info), /* G45_G */ \
-	INTEL_VGA_DEVICE(0x2e32, info), /* G41_G */ \
-	INTEL_VGA_DEVICE(0x2e42, info), /* B43_G */ \
-	INTEL_VGA_DEVICE(0x2e92, info)	/* B43_G.1 */
-
-#define INTEL_PINEVIEW_G_IDS(info) \
-	INTEL_VGA_DEVICE(0xa001, info)
-
-#define INTEL_PINEVIEW_M_IDS(info) \
-	INTEL_VGA_DEVICE(0xa011, info)
-
-#define INTEL_IRONLAKE_D_IDS(info) \
-	INTEL_VGA_DEVICE(0x0042, info)
-
-#define INTEL_IRONLAKE_M_IDS(info) \
-	INTEL_VGA_DEVICE(0x0046, info)
-
-#define INTEL_SNB_D_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x0102, info), \
-	INTEL_VGA_DEVICE(0x010A, info)
-
-#define INTEL_SNB_D_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x0112, info), \
-	INTEL_VGA_DEVICE(0x0122, info)
-
-#define INTEL_SNB_D_IDS(info) \
-	INTEL_SNB_D_GT1_IDS(info), \
-	INTEL_SNB_D_GT2_IDS(info)
-
-#define INTEL_SNB_M_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x0106, info)
-
-#define INTEL_SNB_M_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x0116, info), \
-	INTEL_VGA_DEVICE(0x0126, info)
-
-#define INTEL_SNB_M_IDS(info) \
-	INTEL_SNB_M_GT1_IDS(info), \
-	INTEL_SNB_M_GT2_IDS(info)
-
-#define INTEL_IVB_M_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x0156, info) /* GT1 mobile */
-
-#define INTEL_IVB_M_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x0166, info) /* GT2 mobile */
-
-#define INTEL_IVB_M_IDS(info) \
-	INTEL_IVB_M_GT1_IDS(info), \
-	INTEL_IVB_M_GT2_IDS(info)
-
-#define INTEL_IVB_D_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x0152, info), /* GT1 desktop */ \
-	INTEL_VGA_DEVICE(0x015a, info)  /* GT1 server */
-
-#define INTEL_IVB_D_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x0162, info), /* GT2 desktop */ \
-	INTEL_VGA_DEVICE(0x016a, info)  /* GT2 server */
-
-#define INTEL_IVB_D_IDS(info) \
-	INTEL_IVB_D_GT1_IDS(info), \
-	INTEL_IVB_D_GT2_IDS(info)
-
-#define INTEL_IVB_Q_IDS(info) \
-	INTEL_QUANTA_VGA_DEVICE(info) /* Quanta transcode */
-
-#define INTEL_HSW_ULT_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x0A02, info), /* ULT GT1 desktop */ \
-	INTEL_VGA_DEVICE(0x0A06, info), /* ULT GT1 mobile */ \
-	INTEL_VGA_DEVICE(0x0A0A, info), /* ULT GT1 server */ \
-	INTEL_VGA_DEVICE(0x0A0B, info)  /* ULT GT1 reserved */
-
-#define INTEL_HSW_ULX_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x0A0E, info) /* ULX GT1 mobile */
-
-#define INTEL_HSW_GT1_IDS(info) \
-	INTEL_HSW_ULT_GT1_IDS(info), \
-	INTEL_HSW_ULX_GT1_IDS(info), \
-	INTEL_VGA_DEVICE(0x0402, info), /* GT1 desktop */ \
-	INTEL_VGA_DEVICE(0x0406, info), /* GT1 mobile */ \
-	INTEL_VGA_DEVICE(0x040A, info), /* GT1 server */ \
-	INTEL_VGA_DEVICE(0x040B, info), /* GT1 reserved */ \
-	INTEL_VGA_DEVICE(0x040E, info), /* GT1 reserved */ \
-	INTEL_VGA_DEVICE(0x0C02, info), /* SDV GT1 desktop */ \
-	INTEL_VGA_DEVICE(0x0C06, info), /* SDV GT1 mobile */ \
-	INTEL_VGA_DEVICE(0x0C0A, info), /* SDV GT1 server */ \
-	INTEL_VGA_DEVICE(0x0C0B, info), /* SDV GT1 reserved */ \
-	INTEL_VGA_DEVICE(0x0C0E, info), /* SDV GT1 reserved */ \
-	INTEL_VGA_DEVICE(0x0D02, info), /* CRW GT1 desktop */ \
-	INTEL_VGA_DEVICE(0x0D06, info), /* CRW GT1 mobile */	\
-	INTEL_VGA_DEVICE(0x0D0A, info), /* CRW GT1 server */ \
-	INTEL_VGA_DEVICE(0x0D0B, info), /* CRW GT1 reserved */ \
-	INTEL_VGA_DEVICE(0x0D0E, info)  /* CRW GT1 reserved */
-
-#define INTEL_HSW_ULT_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x0A12, info), /* ULT GT2 desktop */ \
-	INTEL_VGA_DEVICE(0x0A16, info), /* ULT GT2 mobile */	\
-	INTEL_VGA_DEVICE(0x0A1A, info), /* ULT GT2 server */ \
-	INTEL_VGA_DEVICE(0x0A1B, info)  /* ULT GT2 reserved */ \
-
-#define INTEL_HSW_ULX_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x0A1E, info) /* ULX GT2 mobile */ \
-
-#define INTEL_HSW_GT2_IDS(info) \
-	INTEL_HSW_ULT_GT2_IDS(info), \
-	INTEL_HSW_ULX_GT2_IDS(info), \
-	INTEL_VGA_DEVICE(0x0412, info), /* GT2 desktop */ \
-	INTEL_VGA_DEVICE(0x0416, info), /* GT2 mobile */ \
-	INTEL_VGA_DEVICE(0x041A, info), /* GT2 server */ \
-	INTEL_VGA_DEVICE(0x041B, info), /* GT2 reserved */ \
-	INTEL_VGA_DEVICE(0x041E, info), /* GT2 reserved */ \
-	INTEL_VGA_DEVICE(0x0C12, info), /* SDV GT2 desktop */ \
-	INTEL_VGA_DEVICE(0x0C16, info), /* SDV GT2 mobile */ \
-	INTEL_VGA_DEVICE(0x0C1A, info), /* SDV GT2 server */ \
-	INTEL_VGA_DEVICE(0x0C1B, info), /* SDV GT2 reserved */ \
-	INTEL_VGA_DEVICE(0x0C1E, info), /* SDV GT2 reserved */ \
-	INTEL_VGA_DEVICE(0x0D12, info), /* CRW GT2 desktop */ \
-	INTEL_VGA_DEVICE(0x0D16, info), /* CRW GT2 mobile */ \
-	INTEL_VGA_DEVICE(0x0D1A, info), /* CRW GT2 server */ \
-	INTEL_VGA_DEVICE(0x0D1B, info), /* CRW GT2 reserved */ \
-	INTEL_VGA_DEVICE(0x0D1E, info)  /* CRW GT2 reserved */
-
-#define INTEL_HSW_ULT_GT3_IDS(info) \
-	INTEL_VGA_DEVICE(0x0A22, info), /* ULT GT3 desktop */ \
-	INTEL_VGA_DEVICE(0x0A26, info), /* ULT GT3 mobile */ \
-	INTEL_VGA_DEVICE(0x0A2A, info), /* ULT GT3 server */ \
-	INTEL_VGA_DEVICE(0x0A2B, info), /* ULT GT3 reserved */ \
-	INTEL_VGA_DEVICE(0x0A2E, info)  /* ULT GT3 reserved */
-
-#define INTEL_HSW_GT3_IDS(info) \
-	INTEL_HSW_ULT_GT3_IDS(info), \
-	INTEL_VGA_DEVICE(0x0422, info), /* GT3 desktop */ \
-	INTEL_VGA_DEVICE(0x0426, info), /* GT3 mobile */ \
-	INTEL_VGA_DEVICE(0x042A, info), /* GT3 server */ \
-	INTEL_VGA_DEVICE(0x042B, info), /* GT3 reserved */ \
-	INTEL_VGA_DEVICE(0x042E, info), /* GT3 reserved */ \
-	INTEL_VGA_DEVICE(0x0C22, info), /* SDV GT3 desktop */ \
-	INTEL_VGA_DEVICE(0x0C26, info), /* SDV GT3 mobile */ \
-	INTEL_VGA_DEVICE(0x0C2A, info), /* SDV GT3 server */ \
-	INTEL_VGA_DEVICE(0x0C2B, info), /* SDV GT3 reserved */ \
-	INTEL_VGA_DEVICE(0x0C2E, info), /* SDV GT3 reserved */ \
-	INTEL_VGA_DEVICE(0x0D22, info), /* CRW GT3 desktop */ \
-	INTEL_VGA_DEVICE(0x0D26, info), /* CRW GT3 mobile */ \
-	INTEL_VGA_DEVICE(0x0D2A, info), /* CRW GT3 server */ \
-	INTEL_VGA_DEVICE(0x0D2B, info), /* CRW GT3 reserved */ \
-	INTEL_VGA_DEVICE(0x0D2E, info)  /* CRW GT3 reserved */
-
-#define INTEL_HSW_IDS(info) \
-	INTEL_HSW_GT1_IDS(info), \
-	INTEL_HSW_GT2_IDS(info), \
-	INTEL_HSW_GT3_IDS(info)
-
-#define INTEL_VLV_IDS(info) \
-	INTEL_VGA_DEVICE(0x0f30, info), \
-	INTEL_VGA_DEVICE(0x0f31, info), \
-	INTEL_VGA_DEVICE(0x0f32, info), \
-	INTEL_VGA_DEVICE(0x0f33, info)
-
-#define INTEL_BDW_ULT_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x1606, info), /* GT1 ULT */ \
-	INTEL_VGA_DEVICE(0x160B, info)  /* GT1 Iris */
-
-#define INTEL_BDW_ULX_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x160E, info) /* GT1 ULX */
-
-#define INTEL_BDW_GT1_IDS(info) \
-	INTEL_BDW_ULT_GT1_IDS(info), \
-	INTEL_BDW_ULX_GT1_IDS(info), \
-	INTEL_VGA_DEVICE(0x1602, info), /* GT1 ULT */ \
-	INTEL_VGA_DEVICE(0x160A, info), /* GT1 Server */ \
-	INTEL_VGA_DEVICE(0x160D, info)  /* GT1 Workstation */
-
-#define INTEL_BDW_ULT_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x1616, info), /* GT2 ULT */ \
-	INTEL_VGA_DEVICE(0x161B, info)  /* GT2 ULT */
-
-#define INTEL_BDW_ULX_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x161E, info) /* GT2 ULX */
-
-#define INTEL_BDW_GT2_IDS(info) \
-	INTEL_BDW_ULT_GT2_IDS(info), \
-	INTEL_BDW_ULX_GT2_IDS(info), \
-	INTEL_VGA_DEVICE(0x1612, info), /* GT2 Halo */	\
-	INTEL_VGA_DEVICE(0x161A, info), /* GT2 Server */ \
-	INTEL_VGA_DEVICE(0x161D, info)  /* GT2 Workstation */
-
-#define INTEL_BDW_ULT_GT3_IDS(info) \
-	INTEL_VGA_DEVICE(0x1626, info), /* ULT */ \
-	INTEL_VGA_DEVICE(0x162B, info)  /* Iris */ \
-
-#define INTEL_BDW_ULX_GT3_IDS(info) \
-	INTEL_VGA_DEVICE(0x162E, info)  /* ULX */
-
-#define INTEL_BDW_GT3_IDS(info) \
-	INTEL_BDW_ULT_GT3_IDS(info), \
-	INTEL_BDW_ULX_GT3_IDS(info), \
-	INTEL_VGA_DEVICE(0x1622, info), /* ULT */ \
-	INTEL_VGA_DEVICE(0x162A, info), /* Server */ \
-	INTEL_VGA_DEVICE(0x162D, info)  /* Workstation */
-
-#define INTEL_BDW_ULT_RSVD_IDS(info) \
-	INTEL_VGA_DEVICE(0x1636, info), /* ULT */ \
-	INTEL_VGA_DEVICE(0x163B, info)  /* Iris */
-
-#define INTEL_BDW_ULX_RSVD_IDS(info) \
-	INTEL_VGA_DEVICE(0x163E, info) /* ULX */
-
-#define INTEL_BDW_RSVD_IDS(info) \
-	INTEL_BDW_ULT_RSVD_IDS(info), \
-	INTEL_BDW_ULX_RSVD_IDS(info), \
-	INTEL_VGA_DEVICE(0x1632, info), /* ULT */ \
-	INTEL_VGA_DEVICE(0x163A, info), /* Server */ \
-	INTEL_VGA_DEVICE(0x163D, info)  /* Workstation */
-
-#define INTEL_BDW_IDS(info) \
-	INTEL_BDW_GT1_IDS(info), \
-	INTEL_BDW_GT2_IDS(info), \
-	INTEL_BDW_GT3_IDS(info), \
-	INTEL_BDW_RSVD_IDS(info)
-
-#define INTEL_CHV_IDS(info) \
-	INTEL_VGA_DEVICE(0x22b0, info), \
-	INTEL_VGA_DEVICE(0x22b1, info), \
-	INTEL_VGA_DEVICE(0x22b2, info), \
-	INTEL_VGA_DEVICE(0x22b3, info)
-
-#define INTEL_SKL_ULT_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x1906, info), /* ULT GT1 */ \
-	INTEL_VGA_DEVICE(0x1913, info)  /* ULT GT1.5 */
-
-#define INTEL_SKL_ULX_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x190E, info), /* ULX GT1 */ \
-	INTEL_VGA_DEVICE(0x1915, info)  /* ULX GT1.5 */
-
-#define INTEL_SKL_GT1_IDS(info)	\
-	INTEL_SKL_ULT_GT1_IDS(info), \
-	INTEL_SKL_ULX_GT1_IDS(info), \
-	INTEL_VGA_DEVICE(0x1902, info), /* DT  GT1 */ \
-	INTEL_VGA_DEVICE(0x190A, info), /* SRV GT1 */ \
-	INTEL_VGA_DEVICE(0x190B, info), /* Halo GT1 */ \
-	INTEL_VGA_DEVICE(0x1917, info)  /* DT  GT1.5 */
-
-#define INTEL_SKL_ULT_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x1916, info), /* ULT GT2 */ \
-	INTEL_VGA_DEVICE(0x1921, info)  /* ULT GT2F */
-
-#define INTEL_SKL_ULX_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x191E, info) /* ULX GT2 */
-
-#define INTEL_SKL_GT2_IDS(info)	\
-	INTEL_SKL_ULT_GT2_IDS(info), \
-	INTEL_SKL_ULX_GT2_IDS(info), \
-	INTEL_VGA_DEVICE(0x1912, info), /* DT  GT2 */ \
-	INTEL_VGA_DEVICE(0x191A, info), /* SRV GT2 */ \
-	INTEL_VGA_DEVICE(0x191B, info), /* Halo GT2 */ \
-	INTEL_VGA_DEVICE(0x191D, info)  /* WKS GT2 */
-
-#define INTEL_SKL_ULT_GT3_IDS(info) \
-	INTEL_VGA_DEVICE(0x1923, info), /* ULT GT3 */ \
-	INTEL_VGA_DEVICE(0x1926, info), /* ULT GT3e */ \
-	INTEL_VGA_DEVICE(0x1927, info)  /* ULT GT3e */
-
-#define INTEL_SKL_GT3_IDS(info) \
-	INTEL_SKL_ULT_GT3_IDS(info), \
-	INTEL_VGA_DEVICE(0x192A, info), /* SRV GT3 */ \
-	INTEL_VGA_DEVICE(0x192B, info), /* Halo GT3e */ \
-	INTEL_VGA_DEVICE(0x192D, info)  /* SRV GT3e */
-
-#define INTEL_SKL_GT4_IDS(info) \
-	INTEL_VGA_DEVICE(0x1932, info), /* DT GT4 */ \
-	INTEL_VGA_DEVICE(0x193A, info), /* SRV GT4e */ \
-	INTEL_VGA_DEVICE(0x193B, info), /* Halo GT4e */ \
-	INTEL_VGA_DEVICE(0x193D, info) /* WKS GT4e */
-
-#define INTEL_SKL_IDS(info)	 \
-	INTEL_SKL_GT1_IDS(info), \
-	INTEL_SKL_GT2_IDS(info), \
-	INTEL_SKL_GT3_IDS(info), \
-	INTEL_SKL_GT4_IDS(info)
-
-#define INTEL_BXT_IDS(info) \
-	INTEL_VGA_DEVICE(0x0A84, info), \
-	INTEL_VGA_DEVICE(0x1A84, info), \
-	INTEL_VGA_DEVICE(0x1A85, info), \
-	INTEL_VGA_DEVICE(0x5A84, info), /* APL HD Graphics 505 */ \
-	INTEL_VGA_DEVICE(0x5A85, info)  /* APL HD Graphics 500 */
-
-#define INTEL_GLK_IDS(info) \
-	INTEL_VGA_DEVICE(0x3184, info), \
-	INTEL_VGA_DEVICE(0x3185, info)
-
-#define INTEL_KBL_ULT_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x5906, info), /* ULT GT1 */ \
-	INTEL_VGA_DEVICE(0x5913, info)  /* ULT GT1.5 */
-
-#define INTEL_KBL_ULX_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x590E, info), /* ULX GT1 */ \
-	INTEL_VGA_DEVICE(0x5915, info)  /* ULX GT1.5 */
-
-#define INTEL_KBL_GT1_IDS(info)	\
-	INTEL_KBL_ULT_GT1_IDS(info), \
-	INTEL_KBL_ULX_GT1_IDS(info), \
-	INTEL_VGA_DEVICE(0x5902, info), /* DT  GT1 */ \
-	INTEL_VGA_DEVICE(0x5908, info), /* Halo GT1 */ \
-	INTEL_VGA_DEVICE(0x590A, info), /* SRV GT1 */ \
-	INTEL_VGA_DEVICE(0x590B, info) /* Halo GT1 */
-
-#define INTEL_KBL_ULT_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x5916, info), /* ULT GT2 */ \
-	INTEL_VGA_DEVICE(0x5921, info)  /* ULT GT2F */
-
-#define INTEL_KBL_ULX_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x591E, info)  /* ULX GT2 */
-
-#define INTEL_KBL_GT2_IDS(info)	\
-	INTEL_KBL_ULT_GT2_IDS(info), \
-	INTEL_KBL_ULX_GT2_IDS(info), \
-	INTEL_VGA_DEVICE(0x5912, info), /* DT  GT2 */ \
-	INTEL_VGA_DEVICE(0x5917, info), /* Mobile GT2 */ \
-	INTEL_VGA_DEVICE(0x591A, info), /* SRV GT2 */ \
-	INTEL_VGA_DEVICE(0x591B, info), /* Halo GT2 */ \
-	INTEL_VGA_DEVICE(0x591D, info) /* WKS GT2 */
-
-#define INTEL_KBL_ULT_GT3_IDS(info) \
-	INTEL_VGA_DEVICE(0x5926, info) /* ULT GT3 */
-
-#define INTEL_KBL_GT3_IDS(info) \
-	INTEL_KBL_ULT_GT3_IDS(info), \
-	INTEL_VGA_DEVICE(0x5923, info), /* ULT GT3 */ \
-	INTEL_VGA_DEVICE(0x5927, info) /* ULT GT3 */
-
-#define INTEL_KBL_GT4_IDS(info) \
-	INTEL_VGA_DEVICE(0x593B, info) /* Halo GT4 */
-
-/* AML/KBL Y GT2 */
-#define INTEL_AML_KBL_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x591C, info),  /* ULX GT2 */ \
-	INTEL_VGA_DEVICE(0x87C0, info) /* ULX GT2 */
-
-/* AML/CFL Y GT2 */
-#define INTEL_AML_CFL_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x87CA, info)
-
-/* CML GT1 */
-#define INTEL_CML_GT1_IDS(info)	\
-	INTEL_VGA_DEVICE(0x9BA2, info), \
-	INTEL_VGA_DEVICE(0x9BA4, info), \
-	INTEL_VGA_DEVICE(0x9BA5, info), \
-	INTEL_VGA_DEVICE(0x9BA8, info)
-
-#define INTEL_CML_U_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x9B21, info), \
-	INTEL_VGA_DEVICE(0x9BAA, info), \
-	INTEL_VGA_DEVICE(0x9BAC, info)
-
-/* CML GT2 */
-#define INTEL_CML_GT2_IDS(info)	\
-	INTEL_VGA_DEVICE(0x9BC2, info), \
-	INTEL_VGA_DEVICE(0x9BC4, info), \
-	INTEL_VGA_DEVICE(0x9BC5, info), \
-	INTEL_VGA_DEVICE(0x9BC6, info), \
-	INTEL_VGA_DEVICE(0x9BC8, info), \
-	INTEL_VGA_DEVICE(0x9BE6, info), \
-	INTEL_VGA_DEVICE(0x9BF6, info)
-
-#define INTEL_CML_U_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x9B41, info), \
-	INTEL_VGA_DEVICE(0x9BCA, info), \
-	INTEL_VGA_DEVICE(0x9BCC, info)
-
-#define INTEL_KBL_IDS(info) \
-	INTEL_KBL_GT1_IDS(info), \
-	INTEL_KBL_GT2_IDS(info), \
-	INTEL_KBL_GT3_IDS(info), \
-	INTEL_KBL_GT4_IDS(info), \
-	INTEL_AML_KBL_GT2_IDS(info)
-
-/* CFL S */
-#define INTEL_CFL_S_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x3E90, info), /* SRV GT1 */ \
-	INTEL_VGA_DEVICE(0x3E93, info), /* SRV GT1 */ \
-	INTEL_VGA_DEVICE(0x3E99, info)  /* SRV GT1 */
-
-#define INTEL_CFL_S_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x3E91, info), /* SRV GT2 */ \
-	INTEL_VGA_DEVICE(0x3E92, info), /* SRV GT2 */ \
-	INTEL_VGA_DEVICE(0x3E96, info), /* SRV GT2 */ \
-	INTEL_VGA_DEVICE(0x3E98, info), /* SRV GT2 */ \
-	INTEL_VGA_DEVICE(0x3E9A, info)  /* SRV GT2 */
-
-/* CFL H */
-#define INTEL_CFL_H_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x3E9C, info)
-
-#define INTEL_CFL_H_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x3E94, info),  /* Halo GT2 */ \
-	INTEL_VGA_DEVICE(0x3E9B, info) /* Halo GT2 */
-
-/* CFL U GT2 */
-#define INTEL_CFL_U_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x3EA9, info)
-
-/* CFL U GT3 */
-#define INTEL_CFL_U_GT3_IDS(info) \
-	INTEL_VGA_DEVICE(0x3EA5, info), /* ULT GT3 */ \
-	INTEL_VGA_DEVICE(0x3EA6, info), /* ULT GT3 */ \
-	INTEL_VGA_DEVICE(0x3EA7, info), /* ULT GT3 */ \
-	INTEL_VGA_DEVICE(0x3EA8, info)  /* ULT GT3 */
-
-/* WHL/CFL U GT1 */
-#define INTEL_WHL_U_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x3EA1, info), \
-	INTEL_VGA_DEVICE(0x3EA4, info)
-
-/* WHL/CFL U GT2 */
-#define INTEL_WHL_U_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x3EA0, info), \
-	INTEL_VGA_DEVICE(0x3EA3, info)
-
-/* WHL/CFL U GT3 */
-#define INTEL_WHL_U_GT3_IDS(info) \
-	INTEL_VGA_DEVICE(0x3EA2, info)
-
-#define INTEL_CFL_IDS(info)	   \
-	INTEL_CFL_S_GT1_IDS(info), \
-	INTEL_CFL_S_GT2_IDS(info), \
-	INTEL_CFL_H_GT1_IDS(info), \
-	INTEL_CFL_H_GT2_IDS(info), \
-	INTEL_CFL_U_GT2_IDS(info), \
-	INTEL_CFL_U_GT3_IDS(info), \
-	INTEL_WHL_U_GT1_IDS(info), \
-	INTEL_WHL_U_GT2_IDS(info), \
-	INTEL_WHL_U_GT3_IDS(info), \
-	INTEL_AML_CFL_GT2_IDS(info), \
-	INTEL_CML_GT1_IDS(info), \
-	INTEL_CML_GT2_IDS(info), \
-	INTEL_CML_U_GT1_IDS(info), \
-	INTEL_CML_U_GT2_IDS(info)
-
-/* CNL */
-#define INTEL_CNL_PORT_F_IDS(info) \
-	INTEL_VGA_DEVICE(0x5A44, info), \
-	INTEL_VGA_DEVICE(0x5A4C, info), \
-	INTEL_VGA_DEVICE(0x5A54, info), \
-	INTEL_VGA_DEVICE(0x5A5C, info)
-
-#define INTEL_CNL_IDS(info) \
-	INTEL_CNL_PORT_F_IDS(info), \
-	INTEL_VGA_DEVICE(0x5A40, info), \
-	INTEL_VGA_DEVICE(0x5A41, info), \
-	INTEL_VGA_DEVICE(0x5A42, info), \
-	INTEL_VGA_DEVICE(0x5A49, info), \
-	INTEL_VGA_DEVICE(0x5A4A, info), \
-	INTEL_VGA_DEVICE(0x5A50, info), \
-	INTEL_VGA_DEVICE(0x5A51, info), \
-	INTEL_VGA_DEVICE(0x5A52, info), \
-	INTEL_VGA_DEVICE(0x5A59, info), \
-	INTEL_VGA_DEVICE(0x5A5A, info)
-
-/* ICL */
-#define INTEL_ICL_PORT_F_IDS(info) \
-	INTEL_VGA_DEVICE(0x8A50, info), \
-	INTEL_VGA_DEVICE(0x8A52, info), \
-	INTEL_VGA_DEVICE(0x8A53, info), \
-	INTEL_VGA_DEVICE(0x8A54, info), \
-	INTEL_VGA_DEVICE(0x8A56, info), \
-	INTEL_VGA_DEVICE(0x8A57, info), \
-	INTEL_VGA_DEVICE(0x8A58, info),	\
-	INTEL_VGA_DEVICE(0x8A59, info),	\
-	INTEL_VGA_DEVICE(0x8A5A, info), \
-	INTEL_VGA_DEVICE(0x8A5B, info), \
-	INTEL_VGA_DEVICE(0x8A5C, info), \
-	INTEL_VGA_DEVICE(0x8A70, info), \
-	INTEL_VGA_DEVICE(0x8A71, info)
-
-#define INTEL_ICL_11_IDS(info) \
-	INTEL_ICL_PORT_F_IDS(info), \
-	INTEL_VGA_DEVICE(0x8A51, info), \
-	INTEL_VGA_DEVICE(0x8A5D, info)
-
-/* EHL */
-#define INTEL_EHL_IDS(info) \
-	INTEL_VGA_DEVICE(0x4541, info), \
-	INTEL_VGA_DEVICE(0x4551, info), \
-	INTEL_VGA_DEVICE(0x4555, info), \
-	INTEL_VGA_DEVICE(0x4557, info), \
-	INTEL_VGA_DEVICE(0x4571, info)
-
-/* JSL */
-#define INTEL_JSL_IDS(info) \
-	INTEL_VGA_DEVICE(0x4E51, info), \
-	INTEL_VGA_DEVICE(0x4E55, info), \
-	INTEL_VGA_DEVICE(0x4E57, info), \
-	INTEL_VGA_DEVICE(0x4E61, info), \
-	INTEL_VGA_DEVICE(0x4E71, info)
-
-/* TGL */
-#define INTEL_TGL_12_GT1_IDS(info) \
-	INTEL_VGA_DEVICE(0x9A60, info), \
-	INTEL_VGA_DEVICE(0x9A68, info), \
-	INTEL_VGA_DEVICE(0x9A70, info)
-
-#define INTEL_TGL_12_GT2_IDS(info) \
-	INTEL_VGA_DEVICE(0x9A40, info), \
-	INTEL_VGA_DEVICE(0x9A49, info), \
-	INTEL_VGA_DEVICE(0x9A59, info), \
-	INTEL_VGA_DEVICE(0x9A78, info), \
-	INTEL_VGA_DEVICE(0x9AC0, info), \
-	INTEL_VGA_DEVICE(0x9AC9, info), \
-	INTEL_VGA_DEVICE(0x9AD9, info), \
-	INTEL_VGA_DEVICE(0x9AF8, info)
-
-#define INTEL_TGL_12_IDS(info) \
-	INTEL_TGL_12_GT1_IDS(info), \
-	INTEL_TGL_12_GT2_IDS(info)
-
-/* RKL */
-#define INTEL_RKL_IDS(info) \
-	INTEL_VGA_DEVICE(0x4C80, info), \
-	INTEL_VGA_DEVICE(0x4C8A, info), \
-	INTEL_VGA_DEVICE(0x4C8B, info), \
-	INTEL_VGA_DEVICE(0x4C8C, info), \
-	INTEL_VGA_DEVICE(0x4C90, info), \
-	INTEL_VGA_DEVICE(0x4C9A, info)
-
-/* DG1 */
-#define INTEL_DG1_IDS(info) \
-	INTEL_VGA_DEVICE(0x4905, info), \
-	INTEL_VGA_DEVICE(0x4906, info), \
-	INTEL_VGA_DEVICE(0x4907, info), \
-	INTEL_VGA_DEVICE(0x4908, info), \
-	INTEL_VGA_DEVICE(0x4909, info)
-
-/* ADL-S */
-#define INTEL_ADLS_IDS(info) \
-	INTEL_VGA_DEVICE(0x4680, info), \
-	INTEL_VGA_DEVICE(0x4682, info), \
-	INTEL_VGA_DEVICE(0x4688, info), \
-	INTEL_VGA_DEVICE(0x468A, info), \
-	INTEL_VGA_DEVICE(0x4690, info), \
-	INTEL_VGA_DEVICE(0x4692, info), \
-	INTEL_VGA_DEVICE(0x4693, info)
-
-/* ADL-P */
-#define INTEL_ADLP_IDS(info) \
-	INTEL_VGA_DEVICE(0x46A0, info), \
-	INTEL_VGA_DEVICE(0x46A1, info), \
-	INTEL_VGA_DEVICE(0x46A2, info), \
-	INTEL_VGA_DEVICE(0x46A3, info), \
-	INTEL_VGA_DEVICE(0x46A6, info), \
-	INTEL_VGA_DEVICE(0x46A8, info), \
-	INTEL_VGA_DEVICE(0x46AA, info), \
-	INTEL_VGA_DEVICE(0x462A, info), \
-	INTEL_VGA_DEVICE(0x4626, info), \
-	INTEL_VGA_DEVICE(0x4628, info), \
-	INTEL_VGA_DEVICE(0x46B0, info), \
-	INTEL_VGA_DEVICE(0x46B1, info), \
-	INTEL_VGA_DEVICE(0x46B2, info), \
-	INTEL_VGA_DEVICE(0x46B3, info), \
-	INTEL_VGA_DEVICE(0x46C0, info), \
-	INTEL_VGA_DEVICE(0x46C1, info), \
-	INTEL_VGA_DEVICE(0x46C2, info), \
-	INTEL_VGA_DEVICE(0x46C3, info)
-
-/* ADL-N */
-#define INTEL_ADLN_IDS(info) \
-	INTEL_VGA_DEVICE(0x46D0, info), \
-	INTEL_VGA_DEVICE(0x46D1, info), \
-	INTEL_VGA_DEVICE(0x46D2, info)
-
-/* RPL-S */
-#define INTEL_RPLS_IDS(info) \
-        INTEL_VGA_DEVICE(0xA780, info), \
-        INTEL_VGA_DEVICE(0xA781, info), \
-        INTEL_VGA_DEVICE(0xA782, info), \
-        INTEL_VGA_DEVICE(0xA783, info), \
-        INTEL_VGA_DEVICE(0xA788, info), \
-        INTEL_VGA_DEVICE(0xA789, info)
-
-#endif /* _I915_PCIIDS_H */
diff --git a/intel/intel_bufmgr_gem.c b/intel/intel_bufmgr_gem.c
index b28ea74d..4f17667e 100644
--- a/intel/intel_bufmgr_gem.c
+++ b/intel/intel_bufmgr_gem.c
@@ -1,7 +1,7 @@
 /**************************************************************************
  *
- * Copyright � 2007 Red Hat Inc.
- * Copyright � 2007-2012 Intel Corporation
+ * Copyright © 2007 Red Hat Inc.
+ * Copyright © 2007-2012 Intel Corporation
  * Copyright 2006 Tungsten Graphics, Inc., Bismarck, ND., USA
  * All Rights Reserved.
  *
@@ -28,7 +28,7 @@
  *
  **************************************************************************/
 /*
- * Authors: Thomas Hellstr�m <thomas-at-tungstengraphics-dot-com>
+ * Authors: Thomas Hellström <thomas-at-tungstengraphics-dot-com>
  *          Keith Whitwell <keithw-at-tungstengraphics-dot-com>
  *	    Eric Anholt <eric@anholt.net>
  *	    Dave Airlie <airlied@linux.ie>
@@ -1379,25 +1379,26 @@ static void drm_intel_gem_bo_unreference_locked_timed(drm_intel_bo *bo,
 static void drm_intel_gem_bo_unreference(drm_intel_bo *bo)
 {
 	drm_intel_bo_gem *bo_gem = (drm_intel_bo_gem *) bo;
+	drm_intel_bufmgr_gem *bufmgr_gem;
+	struct timespec time;
 
 	assert(atomic_read(&bo_gem->refcount) > 0);
 
-	if (atomic_add_unless(&bo_gem->refcount, -1, 1)) {
-		drm_intel_bufmgr_gem *bufmgr_gem =
-		    (drm_intel_bufmgr_gem *) bo->bufmgr;
-		struct timespec time;
+	if (atomic_add_unless(&bo_gem->refcount, -1, 1))
+		return;
 
-		clock_gettime(CLOCK_MONOTONIC, &time);
+	bufmgr_gem = (drm_intel_bufmgr_gem *) bo->bufmgr;
 
-		pthread_mutex_lock(&bufmgr_gem->lock);
+	clock_gettime(CLOCK_MONOTONIC, &time);
 
-		if (atomic_dec_and_test(&bo_gem->refcount)) {
-			drm_intel_gem_bo_unreference_final(bo, time.tv_sec);
-			drm_intel_gem_cleanup_bo_cache(bufmgr_gem, time.tv_sec);
-		}
+	pthread_mutex_lock(&bufmgr_gem->lock);
 
-		pthread_mutex_unlock(&bufmgr_gem->lock);
+	if (atomic_dec_and_test(&bo_gem->refcount)) {
+		drm_intel_gem_bo_unreference_final(bo, time.tv_sec);
+		drm_intel_gem_cleanup_bo_cache(bufmgr_gem, time.tv_sec);
 	}
+
+	pthread_mutex_unlock(&bufmgr_gem->lock);
 }
 
 static int drm_intel_gem_bo_map(drm_intel_bo *bo, int write_enable)
@@ -3377,16 +3378,17 @@ drm_intel_bufmgr_gem_unref(drm_intel_bufmgr *bufmgr)
 {
 	drm_intel_bufmgr_gem *bufmgr_gem = (drm_intel_bufmgr_gem *)bufmgr;
 
-	if (atomic_add_unless(&bufmgr_gem->refcount, -1, 1)) {
-		pthread_mutex_lock(&bufmgr_list_mutex);
+	if (atomic_add_unless(&bufmgr_gem->refcount, -1, 1))
+		return;
 
-		if (atomic_dec_and_test(&bufmgr_gem->refcount)) {
-			DRMLISTDEL(&bufmgr_gem->managers);
-			drm_intel_bufmgr_gem_destroy(bufmgr);
-		}
+	pthread_mutex_lock(&bufmgr_list_mutex);
 
-		pthread_mutex_unlock(&bufmgr_list_mutex);
+	if (atomic_dec_and_test(&bufmgr_gem->refcount)) {
+		DRMLISTDEL(&bufmgr_gem->managers);
+		drm_intel_bufmgr_gem_destroy(bufmgr);
 	}
+
+	pthread_mutex_unlock(&bufmgr_list_mutex);
 }
 
 drm_public void *drm_intel_gem_bo_map__gtt(drm_intel_bo *bo)
@@ -3588,13 +3590,9 @@ drm_intel_bufmgr_gem_init(int fd, int batch_size)
 		bufmgr_gem->gen = 6;
 	else if (IS_GEN7(bufmgr_gem->pci_device))
 		bufmgr_gem->gen = 7;
-	else if (IS_GEN8(bufmgr_gem->pci_device))
+	else
+		/* Treat all further unmatched platforms the same as gen8 */
 		bufmgr_gem->gen = 8;
-	else if (!intel_get_genx(bufmgr_gem->pci_device, &bufmgr_gem->gen)) {
-		free(bufmgr_gem);
-		bufmgr_gem = NULL;
-		goto exit;
-	}
 
 	if (IS_GEN3(bufmgr_gem->pci_device) &&
 	    bufmgr_gem->gtt_size > 256*1024*1024) {
diff --git a/intel/intel_chipset.c b/intel/intel_chipset.c
deleted file mode 100644
index 99ad04ae..00000000
--- a/intel/intel_chipset.c
+++ /dev/null
@@ -1,94 +0,0 @@
-/*
- * Copyright (C) 2018 Intel Corporation
- *
- * Permission is hereby granted, free of charge, to any person obtaining a
- * copy of this software and associated documentation files (the "Software"),
- * to deal in the Software without restriction, including without limitation
- * the rights to use, copy, modify, merge, publish, distribute, sublicense,
- * and/or sell copies of the Software, and to permit persons to whom the
- * Software is furnished to do so, subject to the following conditions:
- *
- * The above copyright notice and this permission notice (including the next
- * paragraph) shall be included in all copies or substantial portions of the
- * Software.
- *
- * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
- * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
- * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
- * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
- * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
- * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
- * IN THE SOFTWARE.
- */
-#include "intel_chipset.h"
-
-#include <inttypes.h>
-#include <stdbool.h>
-
-#include "i915_pciids.h"
-
-#undef INTEL_VGA_DEVICE
-#define INTEL_VGA_DEVICE(id, gen) { id, gen }
-
-static const struct pci_device {
-	uint16_t device;
-	uint16_t gen;
-} pciids[] = {
-	/* Keep ids sorted by gen; latest gen first */
-	INTEL_RPLS_IDS(12),
-	INTEL_ADLN_IDS(12),
-	INTEL_ADLP_IDS(12),
-	INTEL_ADLS_IDS(12),
-	INTEL_RKL_IDS(12),
-	INTEL_DG1_IDS(12),
-	INTEL_TGL_12_IDS(12),
-	INTEL_JSL_IDS(11),
-	INTEL_EHL_IDS(11),
-	INTEL_ICL_11_IDS(11),
-	INTEL_CNL_IDS(10),
-	INTEL_CFL_IDS(9),
-	INTEL_GLK_IDS(9),
-	INTEL_KBL_IDS(9),
-	INTEL_BXT_IDS(9),
-	INTEL_SKL_IDS(9),
-};
-
-drm_private bool intel_is_genx(unsigned int devid, int gen)
-{
-	const struct pci_device *p,
-		  *pend = pciids + sizeof(pciids) / sizeof(pciids[0]);
-
-	for (p = pciids; p < pend; p++) {
-		/* PCI IDs are sorted */
-		if (p->gen < gen)
-			break;
-
-		if (p->device != devid)
-			continue;
-
-		if (gen == p->gen)
-			return true;
-
-		break;
-	}
-
-	return false;
-}
-
-drm_private bool intel_get_genx(unsigned int devid, int *gen)
-{
-	const struct pci_device *p,
-		  *pend = pciids + sizeof(pciids) / sizeof(pciids[0]);
-
-	for (p = pciids; p < pend; p++) {
-		if (p->device != devid)
-			continue;
-
-		if (gen)
-			*gen = p->gen;
-
-		return true;
-	}
-
-	return false;
-}
diff --git a/intel/intel_chipset.h b/intel/intel_chipset.h
index 0a48e0da..bbf40b9e 100644
--- a/intel/intel_chipset.h
+++ b/intel/intel_chipset.h
@@ -331,20 +331,6 @@
 #include <stdbool.h>
 #include <libdrm_macros.h>
 
-drm_private bool intel_is_genx(unsigned int devid, int gen);
-drm_private bool intel_get_genx(unsigned int devid, int *gen);
-
-#define IS_GEN9(devid) intel_is_genx(devid, 9)
-#define IS_GEN10(devid) intel_is_genx(devid, 10)
-#define IS_GEN11(devid) intel_is_genx(devid, 11)
-#define IS_GEN12(devid) intel_is_genx(devid, 12)
-
-#define IS_9XX(dev)		(IS_GEN3(dev) || \
-				 IS_GEN4(dev) || \
-				 IS_GEN5(dev) || \
-				 IS_GEN6(dev) || \
-				 IS_GEN7(dev) || \
-				 IS_GEN8(dev) || \
-				 intel_get_genx(dev, NULL))
+#define IS_9XX(dev)		(!IS_GEN2(dev))
 
 #endif /* _INTEL_CHIPSET_H */
diff --git a/intel/intel_decode.c b/intel/intel_decode.c
index be6f7798..b0fc2288 100644
--- a/intel/intel_decode.c
+++ b/intel/intel_decode.c
@@ -3817,9 +3817,7 @@ drm_intel_decode_context_alloc(uint32_t devid)
 	struct drm_intel_decode *ctx;
 	int gen = 0;
 
-	if (intel_get_genx(devid, &gen))
-		;
-	else if (IS_GEN8(devid))
+	if (IS_GEN8(devid))
 		gen = 8;
 	else if (IS_GEN7(devid))
 		gen = 7;
@@ -3829,10 +3827,13 @@ drm_intel_decode_context_alloc(uint32_t devid)
 		gen = 5;
 	else if (IS_GEN4(devid))
 		gen = 4;
-	else if (IS_9XX(devid))
+	else if (IS_GEN3(devid))
 		gen = 3;
 	else if (IS_GEN2(devid))
 		gen = 2;
+	else
+		/* Just assume future unknown platforms behave as gen8. */
+		gen = 8;
 
 	if (!gen)
 		return NULL;
diff --git a/intel/meson.build b/intel/meson.build
index e6550daa..2aa9c288 100644
--- a/intel/meson.build
+++ b/intel/meson.build
@@ -23,16 +23,16 @@ libdrm_intel = library(
   [
     files(
       'intel_bufmgr.c', 'intel_bufmgr_fake.c', 'intel_bufmgr_gem.c',
-      'intel_decode.c', 'mm.c', 'intel_chipset.c',
+      'intel_decode.c', 'mm.c',
     ),
     config_file,
   ],
   include_directories : [inc_root, inc_drm],
   link_with : libdrm,
-  dependencies : [dep_pciaccess, dep_pthread_stubs, dep_rt, dep_valgrind, dep_atomic_ops],
+  dependencies : [dep_pciaccess, dep_threads, dep_rt, dep_valgrind, dep_atomic_ops],
   c_args : libdrm_c_args,
   gnu_symbol_visibility : 'hidden',
-  version : '1.0.0',
+  version : '1.@0@.0'.format(patch_ver),
   install : true,
 )
 
@@ -104,6 +104,6 @@ test(
   args : [
     '--lib', libdrm_intel,
     '--symbols-file', files('intel-symbols.txt'),
-    '--nm', prog_nm.path(),
+    '--nm', prog_nm.full_path(),
   ],
 )
diff --git a/intel/test_decode.c b/intel/test_decode.c
index b9f5b927..c47752c9 100644
--- a/intel/test_decode.c
+++ b/intel/test_decode.c
@@ -86,7 +86,8 @@ static void
 compare_batch(struct drm_intel_decode *ctx, const char *batch_filename)
 {
 	FILE *out = NULL;
-	void *ptr, *ref_ptr, *batch_ptr;
+	char *ptr;
+	void *ref_ptr, *batch_ptr;
 #if HAVE_OPEN_MEMSTREAM
 	size_t size;
 #endif
@@ -106,7 +107,7 @@ compare_batch(struct drm_intel_decode *ctx, const char *batch_filename)
 	 * inside of an automake project's test infrastructure.
 	 */
 #if HAVE_OPEN_MEMSTREAM
-	out = open_memstream((char **)&ptr, &size);
+	out = open_memstream(&ptr, &size);
 #else
 	fprintf(stderr, "platform lacks open_memstream, skipping.\n");
 	exit(77);
diff --git a/intel/uthash.h b/intel/uthash.h
index 45d1f9fc..62e16508 100644
--- a/intel/uthash.h
+++ b/intel/uthash.h
@@ -648,11 +648,11 @@ do {
 #define MUR_PLUS2_ALIGNED(p) (((unsigned long)p & 3UL) == 2UL)
 #define MUR_PLUS3_ALIGNED(p) (((unsigned long)p & 3UL) == 3UL)
 #define WP(p) ((uint32_t*)((unsigned long)(p) & ~3UL))
-#if (defined(__BIG_ENDIAN__) || defined(SPARC) || defined(__ppc__) || defined(__ppc64__))
+#ifdef HAVE_BIG_ENDIAN
 #define MUR_THREE_ONE(p) ((((*WP(p))&0x00ffffff) << 8) | (((*(WP(p)+1))&0xff000000) >> 24))
 #define MUR_TWO_TWO(p)   ((((*WP(p))&0x0000ffff) <<16) | (((*(WP(p)+1))&0xffff0000) >> 16))
 #define MUR_ONE_THREE(p) ((((*WP(p))&0x000000ff) <<24) | (((*(WP(p)+1))&0xffffff00) >>  8))
-#else /* assume little endian non-intel */
+#else /* little endian non-intel */
 #define MUR_THREE_ONE(p) ((((*WP(p))&0xffffff00) >> 8) | (((*(WP(p)+1))&0x000000ff) << 24))
 #define MUR_TWO_TWO(p)   ((((*WP(p))&0xffff0000) >>16) | (((*(WP(p)+1))&0x0000ffff) << 16))
 #define MUR_ONE_THREE(p) ((((*WP(p))&0xff000000) >>24) | (((*(WP(p)+1))&0x00ffffff) <<  8))
diff --git a/libsync.h b/libsync.h
index f1a2f96d..c6b64ed3 100644
--- a/libsync.h
+++ b/libsync.h
@@ -33,7 +33,7 @@
 #include <stdint.h>
 #include <string.h>
 #include <sys/ioctl.h>
-#include <sys/poll.h>
+#include <poll.h>
 #include <unistd.h>
 
 #if defined(__cplusplus)
diff --git a/man/drm-kms.7.rst b/man/drm-kms.7.rst
index e91fbe27..587d7eb7 100644
--- a/man/drm-kms.7.rst
+++ b/man/drm-kms.7.rst
@@ -102,13 +102,13 @@ for the selected connector. See the *Examples* section below for more
 information.
 
 All valid modes for a connector can be retrieved with a call to
-drmModeGetConnector3 You need to select the mode you want to use and save it.
+**drmModeGetConnector**\ (3) You need to select the mode you want to use and save it.
 The first mode in the list is the default mode with the highest resolution
 possible and often a suitable choice.
 
 After you have a working connector+CRTC+mode combination, you need to create a
 framebuffer that is used for scanout. Memory buffer allocation is
-driver-depedent and described in **drm-memory**\ (7). You need to create a
+driver-dependent and described in **drm-memory**\ (7). You need to create a
 buffer big enough for your selected mode. Now you can create a framebuffer
 object that uses your memory-buffer as scanout buffer. You can do this with
 **drmModeAddFB**\ (3) and **drmModeAddFB2**\ (3).
diff --git a/man/drm.7.rst b/man/drm.7.rst
index c9b5696f..df2c1c74 100644
--- a/man/drm.7.rst
+++ b/man/drm.7.rst
@@ -73,7 +73,7 @@ driver dependent. However, two generic frameworks are available that are
 used by most DRM drivers. These are the *Translation Table Manager*
 (TTM) and the *Graphics Execution Manager* (GEM). They provide generic
 APIs to create, destroy and access buffers from user-space. However,
-there are still many differences between the drivers so driver-depedent
+there are still many differences between the drivers so driver-dependent
 code is still needed. Many helpers are provided in *libgbm* (Graphics
 Buffer Manager) from the *Mesa* project. For more information on DRM
 memory management, see **drm-memory**\ (7).
diff --git a/meson.build b/meson.build
index 210d29e0..80e92779 100644
--- a/meson.build
+++ b/meson.build
@@ -18,15 +18,26 @@
 # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 # SOFTWARE.
 
+# The versioning should always stay at 2.4.x. If bumping away from this,
+# you must ensure that all users of patch_ver are changed such that DSO versions
+# continuously increment (e.g. blindly bumping from 2.4.122 to 2.5.0 would
+# roll the libdrm DSO versioning from libdrm.so.2.122.0 back to libdrm.so.2.0.0
+# which would be bad)
 project(
   'libdrm',
   ['c'],
-  version : '2.4.110',
+  version : '2.4.122',
   license : 'MIT',
-  meson_version : '>= 0.53',
-  default_options : ['buildtype=debugoptimized', 'c_std=c99'],
+  meson_version : '>= 0.59',
+  default_options : ['buildtype=debugoptimized', 'c_std=c11'],
 )
 
+patch_ver = meson.project_version().split('.')[2]
+
+if ['windows', 'darwin'].contains(host_machine.system())
+  error('unsupported OS: @0@'.format(host_machine.system()))
+endif
+
 pkg = import('pkgconfig')
 
 config = configuration_data()
@@ -34,18 +45,20 @@ config = configuration_data()
 config.set10('UDEV', get_option('udev'))
 with_freedreno_kgsl = get_option('freedreno-kgsl')
 with_install_tests = get_option('install-test-programs')
+with_tests = get_option('tests')
 
-if ['freebsd', 'dragonfly', 'netbsd'].contains(host_machine.system())
-  dep_pthread_stubs = dependency('pthread-stubs', version : '>= 0.4')
-else
-  dep_pthread_stubs = []
-endif
 dep_threads = dependency('threads')
 
 cc = meson.get_compiler('c')
 
 android = cc.compiles('''int func() { return __ANDROID__; }''')
 
+# Solaris / Illumos
+if host_machine.system() == 'sunos'
+  add_global_arguments('-D__EXTENSIONS__', language : 'c')
+  add_global_arguments('-D_POSIX_C_SOURCE=3', language : 'c')
+endif
+
 symbols_check = find_program('symbols-check.py')
 prog_nm = find_program('nm')
 
@@ -82,104 +95,63 @@ endif
 config.set10('HAVE_LIBDRM_ATOMIC_PRIMITIVES', intel_atomics)
 config.set10('HAVE_LIB_ATOMIC_OPS', lib_atomics)
 
-with_intel = false
-_intel = get_option('intel')
-if _intel != 'false'
-  if _intel == 'true' and not with_atomics
-    error('libdrm_intel requires atomics.')
-  else
-    with_intel = _intel == 'true' or host_machine.cpu_family().startswith('x86')
-  endif
-endif
+dep_pciaccess = dependency('pciaccess', version : '>= 0.10', required : get_option('intel'))
+
+with_intel = get_option('intel') \
+  .require(with_atomics, error_message : 'libdrm_intel requires atomics') \
+  .require(dep_pciaccess.found(), error_message : 'libdrm_intel requires libpciaccess') \
+  .disable_auto_if(not host_machine.cpu_family().startswith('x86')) \
+  .allowed()
 summary('Intel', with_intel)
 
-with_radeon = false
-_radeon = get_option('radeon')
-if _radeon != 'false'
-  if _radeon == 'true' and not with_atomics
-    error('libdrm_radeon requires atomics.')
-  endif
-  with_radeon = true
-endif
+with_radeon = get_option('radeon') \
+  .require(with_atomics, error_message : 'libdrm_radeon requires atomics') \
+  .allowed()
 summary('Radeon', with_radeon)
 
-with_amdgpu = false
-_amdgpu = get_option('amdgpu')
-if _amdgpu != 'false'
-  if _amdgpu == 'true' and not with_atomics
-    error('libdrm_amdgpu requires atomics.')
-  endif
-  with_amdgpu = true
-endif
+with_amdgpu = get_option('amdgpu') \
+  .require(with_atomics, error_message : 'libdrm_amdgpu requires atomics') \
+  .allowed()
 summary('AMDGPU', with_amdgpu)
 
-with_nouveau = false
-_nouveau = get_option('nouveau')
-if _nouveau != 'false'
-  if _nouveau == 'true' and not with_atomics
-    error('libdrm_nouveau requires atomics.')
-  endif
-  with_nouveau = true
-endif
+with_nouveau = get_option('nouveau') \
+  .require(with_atomics, error_message : 'libdrm_nouveau requires atomics') \
+  .allowed()
 summary('Nouveau', with_nouveau)
 
-with_vmwgfx = false
-_vmwgfx = get_option('vmwgfx')
-if _vmwgfx != 'false'
-  with_vmwgfx = true
-endif
+with_vmwgfx = get_option('vmwgfx').allowed()
 summary('vmwgfx', with_vmwgfx)
 
-with_omap = false
-_omap = get_option('omap')
-if _omap == 'true'
-  if not with_atomics
-    error('libdrm_omap requires atomics.')
-  endif
-  with_omap = true
-endif
+with_omap = get_option('omap') \
+  .require(with_atomics, error_message : 'libdrm_omap requires atomics') \
+  .enabled()
 summary('OMAP', with_omap)
 
-with_freedreno = false
-_freedreno = get_option('freedreno')
-if _freedreno != 'false'
-  if _freedreno == 'true' and not with_atomics
-    error('libdrm_freedreno requires atomics.')
-  else
-    with_freedreno = _freedreno == 'true' or ['arm', 'aarch64'].contains(host_machine.cpu_family())
-  endif
-endif
+with_freedreno = get_option('freedreno') \
+  .require(with_atomics, error_message : 'libdrm_freedreno requires atomics') \
+  .disable_auto_if(not ['arm', 'aarch64'].contains(host_machine.cpu_family())) \
+  .allowed()
 summary('Freedreno', with_freedreno)
 summary('Freedreon-kgsl', with_freedreno_kgsl)
 
-with_tegra = false
-_tegra = get_option('tegra')
-if _tegra == 'true'
-  if not with_atomics
-    error('libdrm_tegra requires atomics.')
-  endif
-  with_tegra = true
-endif
+with_tegra = get_option('tegra') \
+  .require(with_atomics, error_message : 'libdrm_tegra requires atomics') \
+  .disable_auto_if(not ['arm', 'aarch64'].contains(host_machine.cpu_family())) \
+  .enabled()
 summary('Tegra', with_tegra)
 
-with_etnaviv = false
-_etnaviv = get_option('etnaviv')
-if _etnaviv == 'true'
-  if not with_atomics
-    error('libdrm_etnaviv requires atomics.')
-  endif
-  with_etnaviv = true
-endif
+with_etnaviv = get_option('etnaviv') \
+  .require(with_atomics, error_message : 'libdrm_etnaviv requires atomics') \
+  .disable_auto_if(not ['arm', 'aarch64', 'arc', 'mips', 'mips64', 'loongarch64'].contains(host_machine.cpu_family())) \
+  .allowed()
 summary('Etnaviv', with_etnaviv)
 
-with_exynos = get_option('exynos') == 'true'
+with_exynos = get_option('exynos').enabled()
 summary('EXYNOS', with_exynos)
 
-with_vc4 = false
-_vc4 = get_option('vc4')
-if _vc4 != 'false'
-  with_vc4 = _vc4 == 'true' or ['arm', 'aarch64'].contains(host_machine.cpu_family())
-endif
+with_vc4 = get_option('vc4') \
+  .disable_auto_if(not ['arm', 'aarch64'].contains(host_machine.cpu_family())) \
+  .allowed()
 summary('VC4', with_vc4)
 
 # XXX: Apparently only freebsd and dragonfly bsd actually need this (and
@@ -204,7 +176,6 @@ if not cc.has_function('clock_gettime', prefix : '#define _GNU_SOURCE\n#include
 else
   dep_rt = []
 endif
-dep_m = cc.find_library('m', required : false)
 
 # The header is not required on Linux, and is in fact deprecated in glibc 2.30+
 if ['linux'].contains(host_machine.system())
@@ -243,32 +214,19 @@ libdrm_c_args = cc.get_supported_arguments([
   '-Wno-unused-parameter', '-Wno-attributes', '-Wno-long-long',
   '-Wno-missing-field-initializers'])
 
-dep_pciaccess = dependency('pciaccess', version : '>= 0.10', required : with_intel)
 dep_cunit = dependency('cunit', version : '>= 2.1', required : false)
-_cairo_tests = get_option('cairo-tests')
-if _cairo_tests != 'false'
-  dep_cairo = dependency('cairo', required : _cairo_tests == 'true')
-  with_cairo_tests = dep_cairo.found()
-else
-  dep_cairo = []
-  with_cairo_tests = false
-endif
-_valgrind = get_option('valgrind')
-if _valgrind != 'false'
-  if with_freedreno
-    dep_valgrind = dependency('valgrind', required : _valgrind == 'true', version : '>=3.10.0')
-  else
-    dep_valgrind = dependency('valgrind', required : _valgrind == 'true')
-  endif
-  with_valgrind = dep_valgrind.found()
-else
-  dep_valgrind = []
-  with_valgrind = false
+dep_cairo = dependency('cairo', required : get_option('cairo-tests'))
+with_cairo_tests = dep_cairo.found()
+
+valgrind_version = []
+if with_freedreno
+  valgrind_version = '>=3.10.0'
 endif
+dep_valgrind = dependency('valgrind', required : get_option('valgrind'), version : valgrind_version)
+with_valgrind = dep_valgrind.found()
 
-with_man_pages = get_option('man-pages')
-prog_rst2man = find_program('rst2man', 'rst2man.py', required: with_man_pages == 'true')
-with_man_pages = with_man_pages != 'false' and prog_rst2man.found()
+prog_rst2man = find_program('rst2man', 'rst2man.py', required: get_option('man-pages'))
+with_man_pages = prog_rst2man.found()
 
 config.set10('HAVE_VISIBILITY', cc.has_function_attribute('visibility:hidden'))
 
@@ -289,11 +247,16 @@ if with_freedreno_kgsl and not with_freedreno
   error('cannot enable freedreno-kgsl without freedreno support')
 endif
 config.set10('_GNU_SOURCE', true)
+
+if target_machine.endian() == 'big'
+  config.set('HAVE_BIG_ENDIAN', 1)
+endif
+
 config_file = configure_file(
   configuration : config,
   output : 'config.h',
 )
-add_project_arguments('-include', '@0@'.format(config_file), language : 'c')
+add_project_arguments('-include', meson.current_build_dir() / 'config.h', language : 'c')
 
 inc_root = include_directories('.')
 inc_drm = include_directories('include/drm')
@@ -309,14 +272,14 @@ libdrm_files = [files(
 if android
   libdrm_kw = {}
 else
-  libdrm_kw = {'version' : '2.4.0'}
+  libdrm_kw = { 'version' : '2.@0@.0'.format(patch_ver) }
 endif
 
 libdrm = library(
   'drm',
   libdrm_files,
   c_args : libdrm_c_args,
-  dependencies : [dep_valgrind, dep_rt, dep_m],
+  dependencies : [dep_valgrind, dep_rt],
   include_directories : inc_drm,
   install : true,
   kwargs : libdrm_kw,
@@ -329,7 +292,7 @@ test(
   args : [
     '--lib', libdrm,
     '--symbols-file', files('core-symbols.txt'),
-    '--nm', prog_nm.path(),
+    '--nm', prog_nm.full_path(),
   ],
 )
 
@@ -403,4 +366,6 @@ if with_man_pages
   subdir('man')
 endif
 subdir('data')
-subdir('tests')
+if with_tests
+  subdir('tests')
+endif
diff --git a/meson_options.txt b/meson_options.txt
index 8af33f1c..a72881d7 100644
--- a/meson_options.txt
+++ b/meson_options.txt
@@ -27,100 +27,75 @@ option(
 )
 option(
   'intel',
-  type : 'combo',
-  value : 'auto',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
   description : '''Enable support for Intel's KMS API.''',
 )
 option(
   'radeon',
-  type : 'combo',
-  value : 'auto',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
   description : '''Enable support for radeons's KMS API.''',
 )
 option(
   'amdgpu',
-  type : 'combo',
-  value : 'auto',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
   description : '''Enable support for amdgpu's KMS API.''',
 )
 option(
   'nouveau',
-  type : 'combo',
-  value : 'auto',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
   description : '''Enable support for nouveau's KMS API.''',
 )
 option(
   'vmwgfx',
-  type : 'combo',
-  value : 'true',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
   description : '''Enable support for vmgfx's KMS API.''',
 )
 option(
   'omap',
-  type : 'combo',
-  value : 'false',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
+  value : 'disabled',
   description : '''Enable support for OMAP's experimental KMS API.''',
 )
 option(
   'exynos',
-  type : 'combo',
-  value : 'false',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
+  value : 'disabled',
   description : '''Enable support for EXYNOS's experimental KMS API.''',
 )
 option(
   'freedreno',
-  type : 'combo',
-  value : 'auto',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
   description : '''Enable support for freedreno's KMS API.''',
 )
 option(
   'tegra',
-  type : 'combo',
-  value : 'false',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
+  value : 'disabled',
   description : '''Enable support for Tegra's experimental KMS API.''',
 )
 option(
   'vc4',
-  type : 'combo',
-  value : 'auto',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
   description : '''Enable support for vc4's KMS API.''',
 )
 option(
   'etnaviv',
-  type : 'combo',
-  value : 'false',
-  choices : ['true', 'false', 'auto'],
-  description : '''Enable support for etnaviv's experimental KMS API.''',
+  type : 'feature',
+  description : '''Enable support for etnaviv's KMS API.''',
 )
 option(
   'cairo-tests',
-  type : 'combo',
-  value : 'auto',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
   description : 'Enable support for Cairo rendering in tests.',
 )
 option(
   'man-pages',
-  type : 'combo',
-  value : 'auto',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
   description : 'Enable manpage generation and installation.',
 )
 option(
   'valgrind',
-  type : 'combo',
-  value : 'auto',
-  choices : ['true', 'false', 'auto'],
+  type : 'feature',
   description : 'Build libdrm with valgrind support.',
 )
 option(
@@ -141,3 +116,9 @@ option(
   value : false,
   description : 'Enable support for using udev instead of mknod.',
 )
+option(
+  'tests',
+  type : 'boolean',
+  value : true,
+  description : 'Build test programs.',
+)
diff --git a/nouveau/Makefile.sources b/nouveau/Makefile.sources
deleted file mode 100644
index 89f2a2b5..00000000
--- a/nouveau/Makefile.sources
+++ /dev/null
@@ -1,9 +0,0 @@
-LIBDRM_NOUVEAU_FILES := \
-	nouveau.c \
-	pushbuf.c \
-	bufctx.c \
-	abi16.c \
-	private.h
-
-LIBDRM_NOUVEAU_H_FILES := \
-	nouveau.h
diff --git a/nouveau/meson.build b/nouveau/meson.build
index 350f34c4..ec28dd2d 100644
--- a/nouveau/meson.build
+++ b/nouveau/meson.build
@@ -27,7 +27,7 @@ libdrm_nouveau = library(
   include_directories : [inc_root, inc_drm],
   link_with : libdrm,
   dependencies : [dep_threads, dep_atomic_ops],
-  version : '2.0.0',
+  version : '2.@0@.0'.format(patch_ver),
   install : true,
 )
 
@@ -60,6 +60,6 @@ test(
   args : [
     '--lib', libdrm_nouveau,
     '--symbols-file', files('nouveau-symbols.txt'),
-    '--nm', prog_nm.path(),
+    '--nm', prog_nm.full_path(),
   ],
 )
diff --git a/nouveau/nouveau-symbols.txt b/nouveau/nouveau-symbols.txt
index ef8032f2..7e9b103b 100644
--- a/nouveau/nouveau-symbols.txt
+++ b/nouveau/nouveau-symbols.txt
@@ -1,3 +1,4 @@
+nouveau_bo_make_global
 nouveau_bo_map
 nouveau_bo_name_get
 nouveau_bo_name_ref
@@ -12,6 +13,7 @@ nouveau_bufctx_mthd
 nouveau_bufctx_new
 nouveau_bufctx_refn
 nouveau_bufctx_reset
+nouveau_check_dead_channel
 nouveau_client_del
 nouveau_client_new
 nouveau_device_del
diff --git a/nouveau/nouveau.c b/nouveau/nouveau.c
index 7b4efded..62914a3b 100644
--- a/nouveau/nouveau.c
+++ b/nouveau/nouveau.c
@@ -711,7 +711,7 @@ nouveau_bo_wrap_locked(struct nouveau_device *dev, uint32_t handle,
 }
 
 static void
-nouveau_bo_make_global(struct nouveau_bo_priv *nvbo)
+nouveau_nvbo_make_global(struct nouveau_bo_priv *nvbo)
 {
 	if (!nvbo->head.next) {
 		struct nouveau_device_priv *nvdev = nouveau_device(nvbo->base.device);
@@ -722,6 +722,14 @@ nouveau_bo_make_global(struct nouveau_bo_priv *nvbo)
 	}
 }
 
+drm_public void
+nouveau_bo_make_global(struct nouveau_bo *bo)
+{
+    struct nouveau_bo_priv *nvbo = nouveau_bo(bo);
+
+    nouveau_nvbo_make_global(nvbo);
+}
+
 drm_public int
 nouveau_bo_wrap(struct nouveau_device *dev, uint32_t handle,
 		struct nouveau_bo **pbo)
@@ -780,7 +788,7 @@ nouveau_bo_name_get(struct nouveau_bo *bo, uint32_t *name)
 		}
 		nvbo->name = *name = req.name;
 
-		nouveau_bo_make_global(nvbo);
+		nouveau_nvbo_make_global(nvbo);
 	}
 	return 0;
 }
@@ -830,7 +838,7 @@ nouveau_bo_set_prime(struct nouveau_bo *bo, int *prime_fd)
 	if (ret)
 		return ret;
 
-	nouveau_bo_make_global(nvbo);
+	nouveau_nvbo_make_global(nvbo);
 	return 0;
 }
 
diff --git a/nouveau/nouveau.h b/nouveau/nouveau.h
index 335ce77d..a5119f98 100644
--- a/nouveau/nouveau.h
+++ b/nouveau/nouveau.h
@@ -137,6 +137,7 @@ struct nouveau_bo {
 int nouveau_bo_new(struct nouveau_device *, uint32_t flags, uint32_t align,
 		   uint64_t size, union nouveau_bo_config *,
 		   struct nouveau_bo **);
+void nouveau_bo_make_global(struct nouveau_bo *);
 int nouveau_bo_wrap(struct nouveau_device *, uint32_t handle,
 		    struct nouveau_bo **);
 int nouveau_bo_name_ref(struct nouveau_device *v, uint32_t name,
@@ -273,4 +274,8 @@ struct nv04_notify {
 	uint32_t offset;
 	uint32_t length;
 };
+
+bool
+nouveau_check_dead_channel(struct nouveau_drm *, struct nouveau_object *chan);
+
 #endif
diff --git a/nouveau/pushbuf.c b/nouveau/pushbuf.c
index 5fadd7a9..5d54f21d 100644
--- a/nouveau/pushbuf.c
+++ b/nouveau/pushbuf.c
@@ -782,3 +782,19 @@ nouveau_pushbuf_kick(struct nouveau_pushbuf *push, struct nouveau_object *chan)
 	pushbuf_flush(push);
 	return pushbuf_validate(push, false);
 }
+
+drm_public bool
+nouveau_check_dead_channel(struct nouveau_drm *drm, struct nouveau_object *chan)
+{
+	struct drm_nouveau_gem_pushbuf req = {};
+	struct nouveau_fifo *fifo = chan->data;
+	int ret;
+
+	req.channel = fifo->channel;
+	req.nr_push = 0;
+
+	ret = drmCommandWriteRead(drm->fd, DRM_NOUVEAU_GEM_PUSHBUF,
+				  &req, sizeof(req));
+	/* nouveau returns ENODEV once the channel was killed */
+	return ret == -ENODEV;
+}
diff --git a/omap/meson.build b/omap/meson.build
index 22159184..8187825a 100644
--- a/omap/meson.build
+++ b/omap/meson.build
@@ -25,8 +25,8 @@ libdrm_omap = library(
   c_args : libdrm_c_args,
   gnu_symbol_visibility : 'hidden',
   link_with : libdrm,
-  dependencies : [dep_pthread_stubs, dep_atomic_ops],
-  version : '1.0.0',
+  dependencies : [dep_threads, dep_atomic_ops],
+  version : '1.@0@.0'.format(patch_ver),
   install : true,
 )
 
@@ -56,6 +56,6 @@ test(
   args : [
     '--lib', libdrm_omap,
     '--symbols-file', files('omap-symbols.txt'),
-    '--nm', prog_nm.path(),
+    '--nm', prog_nm.full_path(),
   ],
 )
diff --git a/omap/omap_drm.c b/omap/omap_drm.c
index aa273660..42d35ef7 100644
--- a/omap/omap_drm.c
+++ b/omap/omap_drm.c
@@ -27,7 +27,6 @@
  */
 
 #include <stdlib.h>
-#include <linux/stddef.h>
 #include <linux/types.h>
 #include <errno.h>
 #include <sys/mman.h>
diff --git a/radeon/Makefile.sources b/radeon/Makefile.sources
deleted file mode 100644
index 1cf482a4..00000000
--- a/radeon/Makefile.sources
+++ /dev/null
@@ -1,21 +0,0 @@
-LIBDRM_RADEON_FILES := \
-	radeon_bo_gem.c \
-	radeon_cs_gem.c \
-	radeon_cs_space.c \
-	radeon_bo.c \
-	radeon_cs.c \
-	radeon_surface.c
-
-LIBDRM_RADEON_H_FILES := \
-	radeon_bo.h \
-	radeon_cs.h \
-	radeon_surface.h \
-	radeon_bo_gem.h \
-	radeon_cs_gem.h \
-	radeon_bo_int.h \
-	radeon_cs_int.h \
-	r600_pci_ids.h
-
-LIBDRM_RADEON_BOF_FILES := \
-	bof.c \
-	bof.h
diff --git a/radeon/meson.build b/radeon/meson.build
index 4c1c71e0..bcf3239c 100644
--- a/radeon/meson.build
+++ b/radeon/meson.build
@@ -32,8 +32,8 @@ libdrm_radeon = library(
   gnu_symbol_visibility : 'hidden',
   include_directories : [inc_root, inc_drm],
   link_with : libdrm,
-  dependencies : [dep_pthread_stubs, dep_atomic_ops],
-  version : '1.0.1',
+  dependencies : [dep_threads, dep_atomic_ops],
+  version : '1.@0@.0'.format(patch_ver),
   install : true,
 )
 
@@ -65,6 +65,6 @@ test(
   args : [
     '--lib', libdrm_radeon,
     '--symbols-file', files('radeon-symbols.txt'),
-    '--nm', prog_nm.path(),
+    '--nm', prog_nm.full_path(),
   ],
 )
diff --git a/radeon/radeon_surface.c b/radeon/radeon_surface.c
index ea0a27a9..0ff53a3e 100644
--- a/radeon/radeon_surface.c
+++ b/radeon/radeon_surface.c
@@ -2205,6 +2205,7 @@ static int cik_surface_sanity(struct radeon_surface_manager *surf_man,
         break;
     case RADEON_SURF_MODE_LINEAR_ALIGNED:
     default:
+        *stencil_tile_mode = SI_TILE_MODE_COLOR_LINEAR_ALIGNED;
         *tile_mode = SI_TILE_MODE_COLOR_LINEAR_ALIGNED;
     }
 
diff --git a/symbols-check.py b/symbols-check.py
index 2e7ba68d..c63c0d11 100644
--- a/symbols-check.py
+++ b/symbols-check.py
@@ -7,6 +7,7 @@ import subprocess
 
 # This list contains symbols that _might_ be exported for some platforms
 PLATFORM_SYMBOLS = [
+    '_GLOBAL_OFFSET_TABLE_',
     '__bss_end__',
     '__bss_start__',
     '__bss_start',
@@ -16,6 +17,9 @@ PLATFORM_SYMBOLS = [
     '_end',
     '_fini',
     '_init',
+    '_fbss',
+    '_fdata',
+    '_ftext',
 ]
 
 
diff --git a/tegra/channel.c b/tegra/channel.c
new file mode 100644
index 00000000..39136202
--- /dev/null
+++ b/tegra/channel.c
@@ -0,0 +1,195 @@
+/*
+ * Copyright © 2012, 2013 Thierry Reding
+ * Copyright © 2013 Erik Faye-Lund
+ * Copyright © 2014-2021 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifdef HAVE_CONFIG_H
+#  include "config.h"
+#endif
+
+#include <errno.h>
+#include <string.h>
+
+#include <sys/ioctl.h>
+
+#include "private.h"
+
+drm_public int
+drm_tegra_channel_open(struct drm_tegra *drm,
+                       enum drm_tegra_class client,
+                       struct drm_tegra_channel **channelp)
+{
+    struct drm_tegra_channel_open args;
+    struct drm_tegra_channel *channel;
+    enum host1x_class class;
+    int err;
+
+    switch (client) {
+    case DRM_TEGRA_HOST1X:
+        class = HOST1X_CLASS_HOST1X;
+        break;
+
+    case DRM_TEGRA_GR2D:
+        class = HOST1X_CLASS_GR2D;
+        break;
+
+    case DRM_TEGRA_GR3D:
+        class = HOST1X_CLASS_GR3D;
+        break;
+
+    case DRM_TEGRA_VIC:
+        class = HOST1X_CLASS_VIC;
+        break;
+
+    default:
+        return -EINVAL;
+    }
+
+    channel = calloc(1, sizeof(*channel));
+    if (!channel)
+        return -ENOMEM;
+
+    channel->drm = drm;
+
+    memset(&args, 0, sizeof(args));
+    args.host1x_class = class;
+
+    err = ioctl(drm->fd, DRM_IOCTL_TEGRA_CHANNEL_OPEN, &args);
+    if (err < 0) {
+        free(channel);
+        return -errno;
+    }
+
+    channel->context = args.context;
+    channel->version = args.version;
+    channel->capabilities = args.capabilities;
+    channel->class = class;
+
+    switch (channel->version) {
+    case 0x20:
+    case 0x30:
+    case 0x35:
+    case 0x40:
+    case 0x21:
+        channel->cond_shift = 8;
+        break;
+
+    case 0x18:
+    case 0x19:
+        channel->cond_shift = 10;
+        break;
+
+    default:
+        return -ENOTSUP;
+    }
+
+    *channelp = channel;
+
+    return 0;
+}
+
+drm_public int drm_tegra_channel_close(struct drm_tegra_channel *channel)
+{
+    struct drm_tegra_channel_close args;
+    struct drm_tegra *drm;
+    int err;
+
+    if (!channel)
+        return -EINVAL;
+
+    drm = channel->drm;
+
+    memset(&args, 0, sizeof(args));
+    args.context = channel->context;
+
+    err = ioctl(drm->fd, DRM_IOCTL_TEGRA_CHANNEL_CLOSE, &args);
+    if (err < 0)
+        return -errno;
+
+    free(channel);
+
+    return 0;
+}
+
+drm_public unsigned int
+drm_tegra_channel_get_version(struct drm_tegra_channel *channel)
+{
+    return channel->version;
+}
+
+drm_public int
+drm_tegra_channel_map(struct drm_tegra_channel *channel,
+                      struct drm_tegra_bo *bo, uint32_t flags,
+                      struct drm_tegra_mapping **mapp)
+{
+    struct drm_tegra *drm = channel->drm;
+    struct drm_tegra_channel_map args;
+    struct drm_tegra_mapping *map;
+    int err;
+
+    if (!drm || !bo || !mapp)
+        return -EINVAL;
+
+    map = calloc(1, sizeof(*map));
+    if (!map)
+        return -ENOMEM;
+
+    memset(&args, 0, sizeof(args));
+    args.context = channel->context;
+    args.handle = bo->handle;
+    args.flags = flags;
+
+    err = ioctl(drm->fd, DRM_IOCTL_TEGRA_CHANNEL_MAP, &args);
+    if (err < 0) {
+        free(map);
+        return -errno;
+    }
+
+    map->channel = channel;
+    map->id = args.mapping;
+    *mapp = map;
+
+    return 0;
+}
+
+drm_public int
+drm_tegra_channel_unmap(struct drm_tegra_mapping *map)
+{
+    struct drm_tegra_channel *channel = map->channel;
+    struct drm_tegra *drm = channel->drm;
+    struct drm_tegra_channel_unmap args;
+    int err;
+
+    if (!channel || !map)
+        return -EINVAL;
+
+    memset(&args, 0, sizeof(args));
+    args.context = channel->context;
+    args.mapping = map->id;
+
+    err = ioctl(drm->fd, DRM_IOCTL_TEGRA_CHANNEL_UNMAP, &args);
+    if (err < 0)
+        return -errno;
+
+    free(map);
+    return 0;
+}
diff --git a/tegra/job.c b/tegra/job.c
new file mode 100644
index 00000000..b9af4987
--- /dev/null
+++ b/tegra/job.c
@@ -0,0 +1,187 @@
+/*
+ * Copyright © 2012, 2013 Thierry Reding
+ * Copyright © 2013 Erik Faye-Lund
+ * Copyright © 2014 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifdef HAVE_CONFIG_H
+#  include "config.h"
+#endif
+
+#include <errno.h>
+#include <stdlib.h>
+#include <string.h>
+#include <time.h>
+#include <unistd.h>
+
+#include <sys/ioctl.h>
+#include <poll.h>
+
+#include "private.h"
+
+struct drm_tegra_submit_cmd *
+drm_tegra_job_add_command(struct drm_tegra_job *job, uint32_t type,
+                          uint32_t flags)
+{
+    struct drm_tegra_submit_cmd *commands, *command;
+    size_t size;
+
+    size = (job->num_commands + 1) * sizeof(*commands);
+
+    commands = realloc(job->commands, size);
+    if (!commands)
+        return NULL;
+
+    command = &commands[job->num_commands];
+    memset(command, 0, sizeof(*command));
+    command->type = type;
+    command->flags = flags;
+
+    job->commands = commands;
+    job->num_commands++;
+
+    return command;
+}
+
+drm_public int
+drm_tegra_job_new(struct drm_tegra_channel *channel,
+                  struct drm_tegra_job **jobp)
+{
+    struct drm_tegra_job *job;
+
+    job = calloc(1, sizeof(*job));
+    if (!job)
+        return -ENOMEM;
+
+    job->page_size = sysconf(_SC_PAGESIZE);
+    job->channel = channel;
+
+    *jobp = job;
+
+    return 0;
+}
+
+drm_public int drm_tegra_job_free(struct drm_tegra_job *job)
+{
+    if (!job)
+        return -EINVAL;
+
+    if (job->pushbuf)
+        drm_tegra_pushbuf_free(job->pushbuf);
+
+    if (job->commands)
+        free(job->commands);
+
+    if (job->buffers)
+        free(job->buffers);
+
+    free(job);
+
+    return 0;
+}
+
+drm_public int
+drm_tegra_job_get_pushbuf(struct drm_tegra_job *job,
+                          struct drm_tegra_pushbuf **pushbufp)
+{
+    struct drm_tegra_pushbuf *pushbuf;
+
+    if (!job->pushbuf) {
+        pushbuf = calloc(1, sizeof(*pushbuf));
+        if (!pushbuf)
+            return -ENOMEM;
+
+        pushbuf->job = job;
+
+        pushbuf->start = calloc(1, job->page_size);
+        if (!pushbuf->start) {
+            free(pushbuf);
+            return -ENOMEM;
+        }
+
+        pushbuf->end = pushbuf->start + job->page_size / 4;
+        pushbuf->ptr = pushbuf->start;
+
+        job->pushbuf = pushbuf;
+    }
+
+    *pushbufp = job->pushbuf;
+
+    return 0;
+}
+
+drm_public int
+drm_tegra_job_submit(struct drm_tegra_job *job, struct drm_tegra_fence *fence)
+{
+    struct drm_tegra_channel *channel = job->channel;
+    struct drm_tegra *drm = channel->drm;
+    struct drm_tegra_channel_submit args;
+    int err;
+
+    memset(&args, 0, sizeof(args));
+    args.context = channel->context;
+    args.num_bufs = job->num_buffers;
+    args.num_cmds = job->num_commands;
+    args.gather_data_words = job->pushbuf->ptr - job->pushbuf->start;
+    args.syncpt.id = job->syncpt.id;
+    args.syncpt.increments = job->syncpt.increments;
+
+    args.bufs_ptr = (uintptr_t)job->buffers;
+    args.cmds_ptr = (uintptr_t)job->commands;
+    args.gather_data_ptr = (uintptr_t)job->pushbuf->start;
+
+    err = ioctl(drm->fd, DRM_IOCTL_TEGRA_CHANNEL_SUBMIT, &args);
+    if (err < 0)
+        return -errno;
+
+    job->syncpt.fence = args.syncpt.value;
+
+    if (fence) {
+        fence->drm = drm;
+        fence->syncpt = job->syncpt.id;
+        fence->value = job->syncpt.fence;
+    }
+
+    return 0;
+}
+
+drm_public int
+drm_tegra_job_wait(struct drm_tegra_job *job, unsigned long timeout)
+{
+    struct drm_tegra_channel *channel = job->channel;
+    struct drm_tegra *drm = channel->drm;
+    struct drm_tegra_syncpoint_wait args;
+    struct timespec ts;
+    int err;
+
+    clock_gettime(CLOCK_MONOTONIC, &ts);
+
+    memset(&args, 0, sizeof(args));
+    args.timeout_ns = ts.tv_sec * 1000000000 + ts.tv_nsec + timeout;
+    args.id = job->syncpt.id;
+    args.threshold = job->syncpt.fence;
+
+    err = ioctl(drm->fd, DRM_IOCTL_TEGRA_SYNCPOINT_WAIT, &args);
+    if (err < 0)
+        return -errno;
+
+    return 0;
+}
diff --git a/tegra/meson.build b/tegra/meson.build
index 7585c8b5..dfec91d0 100644
--- a/tegra/meson.build
+++ b/tegra/meson.build
@@ -20,13 +20,18 @@
 
 libdrm_tegra = library(
   'drm_tegra',
-  [files('tegra.c'), config_file],
+  [
+    files(
+      'channel.c', 'job.c', 'private.h', 'pushbuf.c', 'syncpt.c', 'tegra.c'
+    ),
+    config_file
+  ],
   include_directories : [inc_root, inc_drm],
   link_with : libdrm,
-  dependencies : [dep_pthread_stubs, dep_atomic_ops],
+  dependencies : [dep_threads, dep_atomic_ops],
   c_args : libdrm_c_args,
   gnu_symbol_visibility : 'hidden',
-  version : '0.0.0',
+  version : '0.@0@.0'.format(patch_ver),
   install : true,
 )
 
@@ -54,6 +59,6 @@ test(
   args : [
     '--lib', libdrm_tegra,
     '--symbols-file', files('tegra-symbols.txt'),
-    '--nm', prog_nm.path(),
+    '--nm', prog_nm.full_path(),
   ],
 )
diff --git a/tegra/private.h b/tegra/private.h
index bb6c1a51..fc204e82 100644
--- a/tegra/private.h
+++ b/tegra/private.h
@@ -26,26 +26,93 @@
 #define __DRM_TEGRA_PRIVATE_H__ 1
 
 #include <stdbool.h>
+#include <stddef.h>
 #include <stdint.h>
 
 #include <libdrm_macros.h>
 #include <xf86atomic.h>
 
+#include "tegra_drm.h"
 #include "tegra.h"
 
+#define container_of(ptr, type, member) ({                      \
+        const __typeof__(((type *)0)->member) *__mptr = (ptr);  \
+        (type *)((char *)__mptr - offsetof(type, member));      \
+    })
+
+enum host1x_class {
+    HOST1X_CLASS_HOST1X = 0x01,
+    HOST1X_CLASS_GR2D = 0x51,
+    HOST1X_CLASS_GR2D_SB = 0x52,
+    HOST1X_CLASS_VIC = 0x5d,
+    HOST1X_CLASS_GR3D = 0x60,
+};
+
 struct drm_tegra {
-	bool close;
-	int fd;
+    bool close;
+    int fd;
 };
 
 struct drm_tegra_bo {
-	struct drm_tegra *drm;
-	uint32_t handle;
-	uint32_t offset;
-	uint32_t flags;
-	uint32_t size;
-	atomic_t ref;
-	void *map;
+    struct drm_tegra *drm;
+    uint32_t handle;
+    uint64_t offset;
+    uint32_t flags;
+    uint32_t size;
+    atomic_t ref;
+    void *map;
+};
+
+struct drm_tegra_channel {
+    struct drm_tegra *drm;
+    enum host1x_class class;
+    uint32_t capabilities;
+    unsigned int version;
+    uint64_t context;
+
+    unsigned int cond_shift;
+};
+
+struct drm_tegra_mapping {
+    struct drm_tegra_channel *channel;
+    uint32_t id;
+};
+
+struct drm_tegra_pushbuf {
+    struct drm_tegra_job *job;
+
+    uint32_t *start;
+    uint32_t *end;
+    uint32_t *ptr;
+};
+
+void drm_tegra_pushbuf_free(struct drm_tegra_pushbuf *pushbuf);
+
+struct drm_tegra_job {
+    struct drm_tegra_channel *channel;
+    struct drm_tegra_pushbuf *pushbuf;
+    size_t page_size;
+
+    struct drm_tegra_submit_cmd *commands;
+    unsigned int num_commands;
+
+    struct drm_tegra_submit_buf *buffers;
+    unsigned int num_buffers;
+
+    struct {
+        uint32_t id;
+        uint32_t increments;
+        uint32_t fence;
+    } syncpt;
+};
+
+struct drm_tegra_submit_cmd *
+drm_tegra_job_add_command(struct drm_tegra_job *job, uint32_t type,
+                          uint32_t flags);
+
+struct drm_tegra_syncpoint {
+    struct drm_tegra *drm;
+    uint32_t id;
 };
 
 #endif /* __DRM_TEGRA_PRIVATE_H__ */
diff --git a/tegra/pushbuf.c b/tegra/pushbuf.c
new file mode 100644
index 00000000..0c0212e1
--- /dev/null
+++ b/tegra/pushbuf.c
@@ -0,0 +1,184 @@
+/*
+ * Copyright © 2012, 2013 Thierry Reding
+ * Copyright © 2013 Erik Faye-Lund
+ * Copyright © 2014 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifdef HAVE_CONFIG_H
+#  include "config.h"
+#endif
+
+#include <errno.h>
+#include <stdlib.h>
+#include <string.h>
+
+#include "util_math.h"
+#include "private.h"
+
+#define HOST1X_OPCODE_NONINCR(offset, count) \
+    ((0x2 << 28) | (((offset) & 0xfff) << 16) | ((count) & 0xffff))
+
+static inline unsigned int
+drm_tegra_pushbuf_get_offset(struct drm_tegra_pushbuf *pushbuf, uint32_t *ptr)
+{
+    return ptr - pushbuf->start;
+}
+
+void drm_tegra_pushbuf_free(struct drm_tegra_pushbuf *pushbuf)
+{
+    if (pushbuf->start)
+        free(pushbuf->start);
+
+    free(pushbuf);
+}
+
+/**
+ * drm_tegra_pushbuf_begin() - prepare push buffer for a series of pushes
+ * @pushbuf: push buffer
+ * @words: maximum number of words in series of pushes to follow
+ */
+drm_public int
+drm_tegra_pushbuf_begin(struct drm_tegra_pushbuf *pushbuf,
+                        unsigned int words, uint32_t **ptrp)
+{
+    struct drm_tegra_job *job = pushbuf->job;
+    unsigned long offset;
+    size_t size;
+    void *ptr;
+
+    if (pushbuf->ptr + words >= pushbuf->end) {
+        words = pushbuf->end - pushbuf->start + words;
+        size = ALIGN(words * 4, job->page_size);
+        offset = pushbuf->ptr - pushbuf->start;
+
+        ptr = realloc(pushbuf->start, size);
+        if (!ptr)
+            return -ENOMEM;
+
+        pushbuf->start = ptr;
+        pushbuf->end = pushbuf->start + size / 4;
+        pushbuf->ptr = pushbuf->start + offset;
+    }
+
+    if (ptrp)
+        *ptrp = pushbuf->ptr;
+
+    return 0;
+}
+
+drm_public int
+drm_tegra_pushbuf_end(struct drm_tegra_pushbuf *pushbuf, uint32_t *ptr)
+{
+    struct drm_tegra_submit_cmd *command;
+
+    command = drm_tegra_job_add_command(pushbuf->job,
+                                        DRM_TEGRA_SUBMIT_CMD_GATHER_UPTR,
+                                        0);
+    if (!command)
+        return -ENOMEM;
+
+    command->gather_uptr.words = ptr - pushbuf->start;
+    pushbuf->ptr = ptr;
+
+    return 0;
+}
+
+drm_public int
+drm_tegra_pushbuf_wait(struct drm_tegra_pushbuf *pushbuf,
+                       struct drm_tegra_syncpoint *syncpt,
+                       uint32_t value)
+{
+    struct drm_tegra_submit_cmd *command;
+
+    command = drm_tegra_job_add_command(pushbuf->job,
+                                        DRM_TEGRA_SUBMIT_CMD_WAIT_SYNCPT,
+                                        0);
+    if (!command)
+        return -ENOMEM;
+
+    command->wait_syncpt.id = syncpt->id;
+    command->wait_syncpt.value = value;
+
+    return 0;
+}
+
+drm_public int
+drm_tegra_pushbuf_relocate(struct drm_tegra_pushbuf *pushbuf, uint32_t **ptrp,
+                           struct drm_tegra_mapping *target,
+                           unsigned long offset, unsigned int shift,
+                           uint32_t flags)
+{
+    struct drm_tegra_submit_buf *buffers, *buffer;
+    struct drm_tegra_job *job = pushbuf->job;
+    size_t size;
+
+    size = (job->num_buffers + 1) * sizeof(*buffer);
+
+    buffers = realloc(job->buffers, size);
+    if (!buffers)
+        return -ENOMEM;
+
+    buffer = &buffers[job->num_buffers];
+
+    memset(buffer, 0, sizeof(*buffer));
+    buffer->mapping = target->id;
+    buffer->flags = flags;
+    buffer->reloc.target_offset = offset;
+    buffer->reloc.gather_offset_words = drm_tegra_pushbuf_get_offset(pushbuf,
+                                                                     *ptrp);
+    buffer->reloc.shift = shift;
+
+    *(*ptrp)++ = 0xdeadbeef;
+
+    job->buffers = buffers;
+    job->num_buffers++;
+
+    return 0;
+}
+
+drm_public int
+drm_tegra_pushbuf_sync(struct drm_tegra_pushbuf *pushbuf,
+                       struct drm_tegra_syncpoint *syncpt,
+                       unsigned int count)
+{
+    struct drm_tegra_job *job = pushbuf->job;
+
+    job->syncpt.increments += count;
+    job->syncpt.id = syncpt->id;
+
+    return 0;
+}
+
+drm_public int
+drm_tegra_pushbuf_sync_cond(struct drm_tegra_pushbuf *pushbuf, uint32_t **ptrp,
+                            struct drm_tegra_syncpoint *syncpt,
+                            enum drm_tegra_sync_cond cond)
+{
+    struct drm_tegra_channel *channel = pushbuf->job->channel;
+
+    if (cond >= DRM_TEGRA_SYNC_COND_MAX)
+        return -EINVAL;
+
+    *(*ptrp)++ = HOST1X_OPCODE_NONINCR(0x0, 0x1);
+    *(*ptrp)++ = cond << channel->cond_shift | syncpt->id;
+
+    return drm_tegra_pushbuf_sync(pushbuf, syncpt, 1);
+}
diff --git a/tegra/syncpt.c b/tegra/syncpt.c
new file mode 100644
index 00000000..16014186
--- /dev/null
+++ b/tegra/syncpt.c
@@ -0,0 +1,101 @@
+/*
+ * Copyright © 2021 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifdef HAVE_CONFIG_H
+#  include "config.h"
+#endif
+
+#include <errno.h>
+#include <string.h>
+
+#include <sys/ioctl.h>
+
+#include "private.h"
+
+drm_public int
+drm_tegra_syncpoint_new(struct drm_tegra *drm,
+                        struct drm_tegra_syncpoint **syncptp)
+{
+    struct drm_tegra_syncpoint_allocate args;
+    struct drm_tegra_syncpoint *syncpt;
+    int err;
+
+    syncpt = calloc(1, sizeof(*syncpt));
+    if (!syncpt)
+        return -ENOMEM;
+
+    memset(&args, 0, sizeof(args));
+
+    err = ioctl(drm->fd, DRM_IOCTL_TEGRA_SYNCPOINT_ALLOCATE, &args);
+    if (err < 0) {
+        free(syncpt);
+        return -errno;
+    }
+
+    syncpt->drm = drm;
+    syncpt->id = args.id;
+
+    *syncptp = syncpt;
+
+    return 0;
+}
+
+drm_public int
+drm_tegra_syncpoint_free(struct drm_tegra_syncpoint *syncpt)
+{
+    struct drm_tegra_syncpoint_free args;
+    struct drm_tegra *drm = syncpt->drm;
+    int err;
+
+    if (!syncpt)
+        return -EINVAL;
+
+    memset(&args, 0, sizeof(args));
+    args.id = syncpt->id;
+
+    err = ioctl(drm->fd, DRM_IOCTL_TEGRA_SYNCPOINT_FREE, &args);
+    if (err < 0)
+        return -errno;
+
+    free(syncpt);
+
+    return 0;
+}
+
+drm_public int
+drm_tegra_fence_wait(struct drm_tegra_fence *fence, unsigned long timeout)
+{
+    struct drm_tegra_syncpoint_wait args;
+    struct drm_tegra *drm = fence->drm;
+    int err;
+
+    memset(&args, 0, sizeof(args));
+    args.timeout_ns = 0;
+    args.id = fence->syncpt;
+    args.threshold = fence->value;
+
+    err = ioctl(drm->fd, DRM_IOCTL_TEGRA_SYNCPOINT_WAIT, &args);
+    if (err < 0)
+        return -errno;
+
+    return 0;
+}
diff --git a/tegra/tegra-symbols.txt b/tegra/tegra-symbols.txt
index 5e3e955f..1a75c3d2 100644
--- a/tegra/tegra-symbols.txt
+++ b/tegra/tegra-symbols.txt
@@ -1,13 +1,32 @@
-drm_tegra_bo_get_flags
+drm_tegra_bo_export
 drm_tegra_bo_get_handle
-drm_tegra_bo_get_tiling
+drm_tegra_bo_get_name
+drm_tegra_bo_import
 drm_tegra_bo_map
 drm_tegra_bo_new
+drm_tegra_bo_open
 drm_tegra_bo_ref
-drm_tegra_bo_set_flags
-drm_tegra_bo_set_tiling
 drm_tegra_bo_unmap
 drm_tegra_bo_unref
 drm_tegra_bo_wrap
+drm_tegra_channel_close
+drm_tegra_channel_get_version
+drm_tegra_channel_map
+drm_tegra_channel_open
+drm_tegra_channel_unmap
 drm_tegra_close
+drm_tegra_fence_wait
+drm_tegra_job_free
+drm_tegra_job_get_pushbuf
+drm_tegra_job_new
+drm_tegra_job_submit
+drm_tegra_job_wait
 drm_tegra_new
+drm_tegra_pushbuf_begin
+drm_tegra_pushbuf_end
+drm_tegra_pushbuf_relocate
+drm_tegra_pushbuf_sync
+drm_tegra_pushbuf_sync_cond
+drm_tegra_pushbuf_wait
+drm_tegra_syncpoint_free
+drm_tegra_syncpoint_new
diff --git a/tegra/tegra.c b/tegra/tegra.c
index 420b171c..6a51c431 100644
--- a/tegra/tegra.c
+++ b/tegra/tegra.c
@@ -37,288 +37,318 @@
 
 static void drm_tegra_bo_free(struct drm_tegra_bo *bo)
 {
-	struct drm_tegra *drm = bo->drm;
+    struct drm_tegra *drm = bo->drm;
 
-	if (bo->map)
-		munmap(bo->map, bo->size);
+    if (bo->map)
+        munmap(bo->map, bo->size);
 
-	drmCloseBufferHandle(drm->fd, bo->handle);
+    drmCloseBufferHandle(drm->fd, bo->handle);
 
-	free(bo);
+    free(bo);
 }
 
 static int drm_tegra_wrap(struct drm_tegra **drmp, int fd, bool close)
 {
-	struct drm_tegra *drm;
+    struct drm_tegra *drm;
 
-	if (fd < 0 || !drmp)
-		return -EINVAL;
+    if (fd < 0 || !drmp)
+        return -EINVAL;
 
-	drm = calloc(1, sizeof(*drm));
-	if (!drm)
-		return -ENOMEM;
+    drm = calloc(1, sizeof(*drm));
+    if (!drm)
+        return -ENOMEM;
 
-	drm->close = close;
-	drm->fd = fd;
+    drm->close = close;
+    drm->fd = fd;
 
-	*drmp = drm;
+    *drmp = drm;
 
-	return 0;
+    return 0;
 }
 
-drm_public int drm_tegra_new(struct drm_tegra **drmp, int fd)
+drm_public int drm_tegra_new(int fd, struct drm_tegra **drmp)
 {
-	bool supported = false;
-	drmVersionPtr version;
+    bool supported = false;
+    drmVersionPtr version;
 
-	version = drmGetVersion(fd);
-	if (!version)
-		return -ENOMEM;
+    version = drmGetVersion(fd);
+    if (!version)
+        return -ENOMEM;
 
-	if (!strncmp(version->name, "tegra", version->name_len))
-		supported = true;
+    if (!strncmp(version->name, "tegra", version->name_len))
+        supported = true;
 
-	drmFreeVersion(version);
+    drmFreeVersion(version);
 
-	if (!supported)
-		return -ENOTSUP;
+    if (!supported)
+        return -ENOTSUP;
 
-	return drm_tegra_wrap(drmp, fd, false);
+    return drm_tegra_wrap(drmp, fd, false);
 }
 
 drm_public void drm_tegra_close(struct drm_tegra *drm)
 {
-	if (!drm)
-		return;
+    if (!drm)
+        return;
 
-	if (drm->close)
-		close(drm->fd);
+    if (drm->close)
+        close(drm->fd);
 
-	free(drm);
+    free(drm);
 }
 
-drm_public int drm_tegra_bo_new(struct drm_tegra_bo **bop, struct drm_tegra *drm,
-		     uint32_t flags, uint32_t size)
+static struct drm_tegra_bo *drm_tegra_bo_alloc(struct drm_tegra *drm,
+                                               uint32_t handle,
+                                               uint32_t flags,
+                                               uint32_t size)
 {
-	struct drm_tegra_gem_create args;
-	struct drm_tegra_bo *bo;
-	int err;
+    struct drm_tegra_bo *bo;
 
-	if (!drm || size == 0 || !bop)
-		return -EINVAL;
+    bo = calloc(1, sizeof(*bo));
+    if (!bo)
+        return NULL;
 
-	bo = calloc(1, sizeof(*bo));
-	if (!bo)
-		return -ENOMEM;
+    atomic_set(&bo->ref, 1);
+    bo->handle = handle;
+    bo->flags = flags;
+    bo->size = size;
+    bo->drm = drm;
 
-	atomic_set(&bo->ref, 1);
-	bo->flags = flags;
-	bo->size = size;
-	bo->drm = drm;
+    return bo;
+}
+
+drm_public int
+drm_tegra_bo_new(struct drm_tegra *drm, uint32_t flags, uint32_t size,
+                 struct drm_tegra_bo **bop)
+{
+    struct drm_tegra_gem_create args;
+    struct drm_tegra_bo *bo;
+    int err;
+
+    if (!drm || size == 0 || !bop)
+        return -EINVAL;
+
+    bo = drm_tegra_bo_alloc(drm, 0, flags, size);
+    if (!bo)
+        return -ENOMEM;
 
-	memset(&args, 0, sizeof(args));
-	args.flags = flags;
-	args.size = size;
+    memset(&args, 0, sizeof(args));
+    args.flags = flags;
+    args.size = size;
 
-	err = drmCommandWriteRead(drm->fd, DRM_TEGRA_GEM_CREATE, &args,
-				  sizeof(args));
-	if (err < 0) {
-		err = -errno;
-		free(bo);
-		return err;
-	}
+    err = drmCommandWriteRead(drm->fd, DRM_TEGRA_GEM_CREATE, &args,
+                              sizeof(args));
+    if (err < 0) {
+        err = -errno;
+        free(bo);
+        return err;
+    }
 
-	bo->handle = args.handle;
+    bo->handle = args.handle;
 
-	*bop = bo;
+    *bop = bo;
 
-	return 0;
+    return 0;
 }
 
-drm_public int drm_tegra_bo_wrap(struct drm_tegra_bo **bop, struct drm_tegra *drm,
-		      uint32_t handle, uint32_t flags, uint32_t size)
+drm_public int
+drm_tegra_bo_wrap(struct drm_tegra *drm, uint32_t handle, uint32_t flags,
+                  uint32_t size, struct drm_tegra_bo **bop)
 {
-	struct drm_tegra_bo *bo;
+    struct drm_tegra_bo *bo;
 
-	if (!drm || !bop)
-		return -EINVAL;
+    if (!drm || !bop)
+        return -EINVAL;
 
-	bo = calloc(1, sizeof(*bo));
-	if (!bo)
-		return -ENOMEM;
+    bo = drm_tegra_bo_alloc(drm, handle, flags, size);
+    if (!bo)
+        return -ENOMEM;
 
-	atomic_set(&bo->ref, 1);
-	bo->handle = handle;
-	bo->flags = flags;
-	bo->size = size;
-	bo->drm = drm;
+    *bop = bo;
 
-	*bop = bo;
-
-	return 0;
+    return 0;
 }
 
 drm_public struct drm_tegra_bo *drm_tegra_bo_ref(struct drm_tegra_bo *bo)
 {
-	if (bo)
-		atomic_inc(&bo->ref);
+    if (bo)
+        atomic_inc(&bo->ref);
 
-	return bo;
+    return bo;
 }
 
 drm_public void drm_tegra_bo_unref(struct drm_tegra_bo *bo)
 {
-	if (bo && atomic_dec_and_test(&bo->ref))
-		drm_tegra_bo_free(bo);
+    if (bo && atomic_dec_and_test(&bo->ref))
+        drm_tegra_bo_free(bo);
 }
 
-drm_public int drm_tegra_bo_get_handle(struct drm_tegra_bo *bo, uint32_t *handle)
+drm_public int
+drm_tegra_bo_get_handle(struct drm_tegra_bo *bo, uint32_t *handle)
 {
-	if (!bo || !handle)
-		return -EINVAL;
+    if (!bo || !handle)
+        return -EINVAL;
 
-	*handle = bo->handle;
+    *handle = bo->handle;
 
-	return 0;
+    return 0;
 }
 
 drm_public int drm_tegra_bo_map(struct drm_tegra_bo *bo, void **ptr)
 {
-	struct drm_tegra *drm = bo->drm;
+    struct drm_tegra *drm = bo->drm;
 
-	if (!bo->map) {
-		struct drm_tegra_gem_mmap args;
-		int err;
+    if (!bo->map) {
+        struct drm_tegra_gem_mmap args;
+        int err;
 
-		memset(&args, 0, sizeof(args));
-		args.handle = bo->handle;
+        memset(&args, 0, sizeof(args));
+        args.handle = bo->handle;
 
-		err = drmCommandWriteRead(drm->fd, DRM_TEGRA_GEM_MMAP, &args,
-					  sizeof(args));
-		if (err < 0)
-			return -errno;
+        err = drmCommandWriteRead(drm->fd, DRM_TEGRA_GEM_MMAP, &args,
+                                  sizeof(args));
+        if (err < 0)
+            return -errno;
 
-		bo->offset = args.offset;
+        bo->offset = args.offset;
 
-		bo->map = mmap(0, bo->size, PROT_READ | PROT_WRITE, MAP_SHARED,
-			       drm->fd, bo->offset);
-		if (bo->map == MAP_FAILED) {
-			bo->map = NULL;
-			return -errno;
-		}
-	}
+        bo->map = drm_mmap(NULL, bo->size, PROT_READ | PROT_WRITE, MAP_SHARED,
+                           drm->fd, bo->offset);
+        if (bo->map == MAP_FAILED) {
+            bo->map = NULL;
+            return -errno;
+        }
+    }
 
-	if (ptr)
-		*ptr = bo->map;
+    if (ptr)
+        *ptr = bo->map;
 
-	return 0;
+    return 0;
 }
 
 drm_public int drm_tegra_bo_unmap(struct drm_tegra_bo *bo)
 {
-	if (!bo)
-		return -EINVAL;
+    if (!bo)
+        return -EINVAL;
 
-	if (!bo->map)
-		return 0;
+    if (!bo->map)
+        return 0;
 
-	if (munmap(bo->map, bo->size))
-		return -errno;
+    if (munmap(bo->map, bo->size))
+        return -errno;
 
-	bo->map = NULL;
+    bo->map = NULL;
 
-	return 0;
+    return 0;
 }
 
-drm_public int drm_tegra_bo_get_flags(struct drm_tegra_bo *bo, uint32_t *flags)
+drm_public int drm_tegra_bo_get_name(struct drm_tegra_bo *bo, uint32_t *name)
 {
-	struct drm_tegra_gem_get_flags args;
-	struct drm_tegra *drm = bo->drm;
-	int err;
-
-	if (!bo)
-		return -EINVAL;
+    struct drm_tegra *drm = bo->drm;
+    struct drm_gem_flink args;
+    int err;
 
-	memset(&args, 0, sizeof(args));
-	args.handle = bo->handle;
+    memset(&args, 0, sizeof(args));
+    args.handle = bo->handle;
 
-	err = drmCommandWriteRead(drm->fd, DRM_TEGRA_GEM_GET_FLAGS, &args,
-				  sizeof(args));
-	if (err < 0)
-		return -errno;
+    err = drmIoctl(drm->fd, DRM_IOCTL_GEM_FLINK, &args);
+    if (err < 0)
+        return err;
 
-	if (flags)
-		*flags = args.flags;
+    if (name)
+        *name = args.name;
 
-	return 0;
+    return 0;
 }
 
-drm_public int drm_tegra_bo_set_flags(struct drm_tegra_bo *bo, uint32_t flags)
+drm_public int
+drm_tegra_bo_open(struct drm_tegra *drm, uint32_t name, uint32_t flags,
+                  struct drm_tegra_bo **bop)
 {
-	struct drm_tegra_gem_get_flags args;
-	struct drm_tegra *drm = bo->drm;
-	int err;
+    struct drm_gem_open args;
+    struct drm_tegra_bo *bo;
+    int err;
+
+    bo = drm_tegra_bo_alloc(drm, 0, flags, 0);
+    if (!bo)
+        return -ENOMEM;
+
+    memset(&args, 0, sizeof(args));
+    args.name = name;
 
-	if (!bo)
-		return -EINVAL;
+    err = drmIoctl(drm->fd, DRM_IOCTL_GEM_OPEN, &args);
+    if (err < 0)
+        goto free;
 
-	memset(&args, 0, sizeof(args));
-	args.handle = bo->handle;
-	args.flags = flags;
+    bo->handle = args.handle;
+    bo->size = args.size;
 
-	err = drmCommandWriteRead(drm->fd, DRM_TEGRA_GEM_SET_FLAGS, &args,
-				  sizeof(args));
-	if (err < 0)
-		return -errno;
+    *bop = bo;
 
-	return 0;
+    return 0;
+
+free:
+    free(bo);
+    return err;
 }
 
-drm_public int drm_tegra_bo_get_tiling(struct drm_tegra_bo *bo,
-			    struct drm_tegra_bo_tiling *tiling)
+drm_public int drm_tegra_bo_export(struct drm_tegra_bo *bo, uint32_t flags)
 {
-	struct drm_tegra_gem_get_tiling args;
-	struct drm_tegra *drm = bo->drm;
-	int err;
+    int fd, err;
+
+    flags |= DRM_CLOEXEC;
+
+    err = drmPrimeHandleToFD(bo->drm->fd, bo->handle, flags, &fd);
+    if (err < 0)
+        return err;
+
+    return fd;
+}
 
-	if (!bo)
-		return -EINVAL;
+static ssize_t fd_get_size(int fd)
+{
+    ssize_t size, offset;
+    int err;
 
-	memset(&args, 0, sizeof(args));
-	args.handle = bo->handle;
+    offset = lseek(fd, 0, SEEK_CUR);
+    if (offset < 0)
+        return -errno;
 
-	err = drmCommandWriteRead(drm->fd, DRM_TEGRA_GEM_GET_TILING, &args,
-				  sizeof(args));
-	if (err < 0)
-		return -errno;
+    size = lseek(fd, 0, SEEK_END);
+    if (size < 0)
+        return -errno;
 
-	if (tiling) {
-		tiling->mode = args.mode;
-		tiling->value = args.value;
-	}
+    err = lseek(fd, offset, SEEK_SET);
+    if (err < 0)
+        return -errno;
 
-	return 0;
+    return size;
 }
 
-drm_public int drm_tegra_bo_set_tiling(struct drm_tegra_bo *bo,
-			    const struct drm_tegra_bo_tiling *tiling)
+drm_public int
+drm_tegra_bo_import(struct drm_tegra *drm, int fd, struct drm_tegra_bo **bop)
 {
-	struct drm_tegra_gem_set_tiling args;
-	struct drm_tegra *drm = bo->drm;
-	int err;
+    struct drm_tegra_bo *bo;
+    ssize_t size;
+    int err;
+
+    size = fd_get_size(fd);
+    if (size < 0)
+        return size;
+
+    bo = drm_tegra_bo_alloc(drm, 0, 0, size);
+    if (!bo)
+        return -ENOMEM;
 
-	if (!bo)
-		return -EINVAL;
+    err = drmPrimeFDToHandle(drm->fd, fd, &bo->handle);
+    if (err < 0)
+        goto free;
 
-	memset(&args, 0, sizeof(args));
-	args.handle = bo->handle;
-	args.mode = tiling->mode;
-	args.value = tiling->value;
+    *bop = bo;
 
-	err = drmCommandWriteRead(drm->fd, DRM_TEGRA_GEM_SET_TILING, &args,
-				  sizeof(args));
-	if (err < 0)
-		return -errno;
+    return 0;
 
-	return 0;
+free:
+    free(bo);
+    return err;
 }
diff --git a/tegra/tegra.h b/tegra/tegra.h
index 31b0995a..8f3c0554 100644
--- a/tegra/tegra.h
+++ b/tegra/tegra.h
@@ -28,33 +28,100 @@
 #include <stdint.h>
 #include <stdlib.h>
 
+#include <tegra_drm.h>
+
+enum drm_tegra_class {
+    DRM_TEGRA_HOST1X,
+    DRM_TEGRA_GR2D,
+    DRM_TEGRA_GR3D,
+    DRM_TEGRA_VIC,
+};
+
 struct drm_tegra_bo;
 struct drm_tegra;
 
-int drm_tegra_new(struct drm_tegra **drmp, int fd);
+int drm_tegra_new(int fd, struct drm_tegra **drmp);
 void drm_tegra_close(struct drm_tegra *drm);
 
-int drm_tegra_bo_new(struct drm_tegra_bo **bop, struct drm_tegra *drm,
-		     uint32_t flags, uint32_t size);
-int drm_tegra_bo_wrap(struct drm_tegra_bo **bop, struct drm_tegra *drm,
-		      uint32_t handle, uint32_t flags, uint32_t size);
+int drm_tegra_bo_new(struct drm_tegra *drm, uint32_t flags, uint32_t size,
+                     struct drm_tegra_bo **bop);
+int drm_tegra_bo_wrap(struct drm_tegra *drm, uint32_t handle, uint32_t flags,
+                      uint32_t size, struct drm_tegra_bo **bop);
 struct drm_tegra_bo *drm_tegra_bo_ref(struct drm_tegra_bo *bo);
 void drm_tegra_bo_unref(struct drm_tegra_bo *bo);
 int drm_tegra_bo_get_handle(struct drm_tegra_bo *bo, uint32_t *handle);
 int drm_tegra_bo_map(struct drm_tegra_bo *bo, void **ptr);
 int drm_tegra_bo_unmap(struct drm_tegra_bo *bo);
 
-int drm_tegra_bo_get_flags(struct drm_tegra_bo *bo, uint32_t *flags);
-int drm_tegra_bo_set_flags(struct drm_tegra_bo *bo, uint32_t flags);
+int drm_tegra_bo_get_name(struct drm_tegra_bo *bo, uint32_t *name);
+int drm_tegra_bo_open(struct drm_tegra *drm, uint32_t name, uint32_t flags,
+                      struct drm_tegra_bo **bop);
+
+int drm_tegra_bo_export(struct drm_tegra_bo *bo, uint32_t flags);
+int drm_tegra_bo_import(struct drm_tegra *drm, int fd,
+                        struct drm_tegra_bo **bop);
+
+struct drm_tegra_channel;
+struct drm_tegra_mapping;
+struct drm_tegra_pushbuf;
+struct drm_tegra_job;
+struct drm_tegra_syncpoint;
 
-struct drm_tegra_bo_tiling {
-	uint32_t mode;
-	uint32_t value;
+enum drm_tegra_sync_cond {
+    DRM_TEGRA_SYNC_COND_IMMEDIATE,
+    DRM_TEGRA_SYNC_COND_OP_DONE,
+    DRM_TEGRA_SYNC_COND_RD_DONE,
+    DRM_TEGRA_SYNC_COND_WR_SAFE,
+    DRM_TEGRA_SYNC_COND_MAX,
+  };
+
+struct drm_tegra_fence {
+    struct drm_tegra *drm;
+    uint32_t syncpt;
+    uint32_t value;
 };
 
-int drm_tegra_bo_get_tiling(struct drm_tegra_bo *bo,
-			    struct drm_tegra_bo_tiling *tiling);
-int drm_tegra_bo_set_tiling(struct drm_tegra_bo *bo,
-			    const struct drm_tegra_bo_tiling *tiling);
+int drm_tegra_channel_open(struct drm_tegra *drm,
+                           enum drm_tegra_class client,
+                           struct drm_tegra_channel **channelp);
+int drm_tegra_channel_close(struct drm_tegra_channel *channel);
+unsigned int drm_tegra_channel_get_version(struct drm_tegra_channel *channel);
+int drm_tegra_channel_map(struct drm_tegra_channel *channel,
+                          struct drm_tegra_bo *bo, uint32_t flags,
+                          struct drm_tegra_mapping **mapp);
+int drm_tegra_channel_unmap(struct drm_tegra_mapping *map);
+
+int drm_tegra_job_new(struct drm_tegra_channel *channel,
+                      struct drm_tegra_job **jobp);
+int drm_tegra_job_free(struct drm_tegra_job *job);
+int drm_tegra_job_get_pushbuf(struct drm_tegra_job *job,
+                              struct drm_tegra_pushbuf **pushbufp);
+int drm_tegra_job_submit(struct drm_tegra_job *job,
+                         struct drm_tegra_fence *fence);
+int drm_tegra_job_wait(struct drm_tegra_job *job, unsigned long timeout);
+
+int drm_tegra_pushbuf_begin(struct drm_tegra_pushbuf *pushbuf,
+                            unsigned int words, uint32_t **ptrp);
+int drm_tegra_pushbuf_end(struct drm_tegra_pushbuf *pushbuf, uint32_t *ptr);
+int drm_tegra_pushbuf_wait(struct drm_tegra_pushbuf *pushbuf,
+                           struct drm_tegra_syncpoint *syncpt,
+                           uint32_t value);
+int drm_tegra_pushbuf_relocate(struct drm_tegra_pushbuf *pushbuf,
+                               uint32_t **ptrp,
+                               struct drm_tegra_mapping *target,
+                               unsigned long offset, unsigned int shift,
+                               uint32_t flags);
+int drm_tegra_pushbuf_sync(struct drm_tegra_pushbuf *pushbuf,
+                           struct drm_tegra_syncpoint *syncpt,
+                           unsigned int count);
+int drm_tegra_pushbuf_sync_cond(struct drm_tegra_pushbuf *pushbuf,
+                                uint32_t **ptrp,
+                                struct drm_tegra_syncpoint *syncpt,
+                                enum drm_tegra_sync_cond cond);
+
+int drm_tegra_syncpoint_new(struct drm_tegra *drm,
+                            struct drm_tegra_syncpoint **syncptp);
+int drm_tegra_syncpoint_free(struct drm_tegra_syncpoint *syncpt);
+int drm_tegra_fence_wait(struct drm_tegra_fence *fence, unsigned long timeout);
 
 #endif /* __DRM_TEGRA_H__ */
diff --git a/tests/amdgpu/amdgpu_stress.c b/tests/amdgpu/amdgpu_stress.c
index 5c5c88c5..f919351e 100644
--- a/tests/amdgpu/amdgpu_stress.c
+++ b/tests/amdgpu/amdgpu_stress.c
@@ -30,6 +30,7 @@
 #include <errno.h>
 #include <unistd.h>
 #include <stdlib.h>
+#include <inttypes.h>
 
 #include "drm.h"
 #include "xf86drmMode.h"
@@ -175,7 +176,7 @@ int alloc_bo(uint32_t domain, uint64_t size)
 
 	resources[num_buffers] = bo;
 	virtual[num_buffers] = addr;
-	fprintf(stdout, "Allocated BO number %u at 0x%lx, domain 0x%x, size %lu\n",
+	fprintf(stdout, "Allocated BO number %u at 0x%" PRIx64 ", domain 0x%x, size %" PRIu64 "\n",
 		num_buffers++, addr, domain, size);
 	return 0;
 }
@@ -273,7 +274,7 @@ int submit_ib(uint32_t from, uint32_t to, uint64_t size, uint32_t count)
 	delta = stop.tv_nsec + stop.tv_sec * 1000000000UL;
 	delta -= start.tv_nsec + start.tv_sec * 1000000000UL;
 
-	fprintf(stdout, "Submitted %u IBs to copy from %u(%lx) to %u(%lx) %lu bytes took %lu usec\n",
+	fprintf(stdout, "Submitted %u IBs to copy from %u(%" PRIx64 ") to %u(%" PRIx64 ") %" PRIu64 " bytes took %" PRIu64 " usec\n",
 		count, from, virtual[from], to, virtual[to], copied, delta / 1000);
 	return 0;
 }
@@ -293,7 +294,7 @@ uint64_t parse_size(void)
 	char ext[2];
 
 	ext[0] = 0;
-	if (sscanf(optarg, "%li%1[kmgKMG]", &size, ext) < 1) {
+	if (sscanf(optarg, "%" PRIi64 "%1[kmgKMG]", &size, ext) < 1) {
 		fprintf(stderr, "Can't parse size arg: %s\n", optarg);
 		exit(EXIT_FAILURE);
 	}
@@ -375,7 +376,7 @@ int main(int argc, char **argv)
 			next_arg(argc, argv, "Missing buffer size");
 			size = parse_size();
 			if (size < getpagesize()) {
-				fprintf(stderr, "Buffer size to small %lu\n", size);
+				fprintf(stderr, "Buffer size to small %" PRIu64 "\n", size);
 				exit(EXIT_FAILURE);
 			}
 			r = alloc_bo(domain, size);
diff --git a/tests/amdgpu/amdgpu_test.c b/tests/amdgpu/amdgpu_test.c
index 6a2ff8ba..ec787889 100644
--- a/tests/amdgpu/amdgpu_test.c
+++ b/tests/amdgpu/amdgpu_test.c
@@ -73,6 +73,7 @@
 #define SYNCOBJ_TIMELINE_TESTS_STR "SYNCOBJ TIMELINE Tests"
 #define SECURITY_TESTS_STR "Security Tests"
 #define HOTUNPLUG_TESTS_STR "Hotunplug Tests"
+#define CP_DMA_TESTS_STR "CP DMA Tests"
 
 /**
  *  Open handles for amdgpu devices
@@ -163,6 +164,12 @@ static CU_SuiteInfo suites[] = {
 		.pCleanupFunc = suite_hotunplug_tests_clean,
 		.pTests = hotunplug_tests,
 	},
+	{
+		.pName = CP_DMA_TESTS_STR,
+		.pInitFunc = suite_cp_dma_tests_init,
+		.pCleanupFunc = suite_cp_dma_tests_clean,
+		.pTests = cp_dma_tests,
+	},
 
 	CU_SUITE_INFO_NULL,
 };
@@ -232,6 +239,10 @@ static Suites_Active_Status suites_active_stat[] = {
 			.pName = HOTUNPLUG_TESTS_STR,
 			.pActive = suite_hotunplug_tests_enable,
 		},
+		{
+			.pName = CP_DMA_TESTS_STR,
+			.pActive = suite_cp_dma_tests_enable,
+		},
 };
 
 
@@ -285,18 +296,23 @@ static void display_test_suites(void)
 
 /** Help string for command line parameters */
 static const char usage[] =
-	"Usage: %s [-hlpr] [<-s <suite id>> [-t <test id>] [-f]] "
-	"[-b <pci_bus_id> [-d <pci_device_id>]]\n"
-	"where:\n"
-	"       l - Display all suites and their tests\n"
-	"       r - Run the tests on render node\n"
-	"       b - Specify device's PCI bus id to run tests\n"
-	"       d - Specify device's PCI device id to run tests (optional)\n"
-	"       p - Display information of AMDGPU devices in system\n"
-	"       f - Force executing inactive suite or test\n"
-	"       h - Display this help\n";
+	"Usage: %s [-hlpr] [-s <suite id>] [-e <s>[.<t>] [-e ...]] [-t <test id>] [-f] "
+	"[-b <pci_bus_id>] [-d <pci_device_id>]\n"
+	"Where,\n"
+	"  -b      Specify device's PCI bus id to run tests\n"
+	"  -d      Specify device's PCI device id to run tests (optional)\n"
+	"  -e <s>[.<t>]  Disable test <t> of suite <s>. If only <s> is given, then disable\n"
+	"          the whole suite. Can be specified more than once on the command line\n"
+	"          to disable multiple tests or suites.\n"
+	"  -f      Force executing inactive suite or test\n"
+	"  -h      Display this help\n"
+	"  -l      Display all test suites and their tests\n"
+	"  -p      Display information of AMDGPU devices in system\n"
+	"  -r      Run the tests on render node\n"
+	"  -s <s>  Enable only test suite <s>\n"
+	"  -t <t>  Enable only test <t> of test suite <s>\n";
 /** Specified options strings for getopt */
-static const char options[]   = "hlrps:t:b:d:f";
+static const char options[]   = "hlrps:t:e:b:d:f";
 
 /* Open AMD devices.
  * Return the number of AMD device opened.
@@ -311,6 +327,10 @@ static int amdgpu_open_devices(int open_render_node)
 	int fd;
 	drmVersionPtr version;
 
+	for (i = 0; i < MAX_CARDS_SUPPORTED; i++) {
+		drm_amdgpu[i] = -1;
+	}
+
 	drm_count = drmGetDevices2(0, devices, MAX_CARDS_SUPPORTED);
 
 	if (drm_count < 0) {
@@ -534,6 +554,14 @@ static void amdgpu_disable_suites()
 				"gfx ring slow bad draw test (set amdgpu.lockup_timeout=50)", CU_FALSE))
 			fprintf(stderr, "test deactivation failed - %s\n", CU_get_error_msg());
 
+	if (amdgpu_set_test_active(DEADLOCK_TESTS_STR,
+			"sdma ring corrupted header test (set amdgpu.lockup_timeout=50)", CU_FALSE))
+		fprintf(stderr, "test deactivation failed - %s\n", CU_get_error_msg());
+
+	if (amdgpu_set_test_active(DEADLOCK_TESTS_STR,
+			"sdma ring slow linear copy test (set amdgpu.lockup_timeout=50)", CU_FALSE))
+		fprintf(stderr, "test deactivation failed - %s\n", CU_get_error_msg());
+
 	if (amdgpu_set_test_active(BASIC_TESTS_STR, "bo eviction Test", CU_FALSE))
 		fprintf(stderr, "test deactivation failed - %s\n", CU_get_error_msg());
 
@@ -639,6 +667,48 @@ char *amdgpu_get_device_from_fd(int fd)
 #endif
 }
 
+#ifndef ARRAY_SIZE
+#define ARRAY_SIZE(_A) (sizeof(_A)/sizeof(_A[0]))
+#endif
+
+static void amdgpu_test_disable(long suite, long test)
+{
+	const char *suite_name;
+
+	if (suite < 1)
+		return;
+
+	/* The array is 0-based, so subract 1. */
+	suite--;
+	if (suite >= ARRAY_SIZE(suites) - 1)
+		return;
+
+	suite_name = suites[suite].pName;
+	if (test < 1) {
+		fprintf(stderr, "Deactivating suite %s\n", suite_name);
+		amdgpu_set_suite_active(suite_name, CU_FALSE);
+	} else {
+		int ii;
+
+		/* The array is 0-based so subtract 1. */
+		test--;
+		for (ii = 0; suites[suite].pTests[ii].pName; ii++) {
+			if (ii == test) {
+				fprintf(stderr, "Deactivating %s:%s\n",
+					suite_name,
+					suites[suite].pTests[ii].pName);
+				amdgpu_set_test_active(suite_name,
+						       suites[suite].pTests[ii].pName,
+						       CU_FALSE);
+				break;
+			}
+		}
+
+		if (suites[suite].pTests[ii].pName == NULL)
+			fprintf(stderr, "No such suite.test %ld.%ld\n", suite, test);
+	}
+}
+
 /* The main() function for setting up and running the tests.
  * Returns a CUE_SUCCESS on successful running, another
  * CUnit error code on failure.
@@ -657,48 +727,21 @@ int main(int argc, char **argv)
 	int display_list = 0;
 	int force_run = 0;
 
-	for (i = 0; i < MAX_CARDS_SUPPORTED; i++)
-		drm_amdgpu[i] = -1;
-
-
-	/* Parse command line string */
+	/* Parse command line string.
+	 * Process various command line options as early as possible.
+	 */
 	opterr = 0;		/* Do not print error messages from getopt */
 	while ((c = getopt(argc, argv, options)) != -1) {
 		switch (c) {
-		case 'l':
-			display_list = 1;
-			break;
-		case 's':
-			suite_id = atoi(optarg);
-			break;
-		case 't':
-			test_id = atoi(optarg);
-			break;
-		case 'b':
-			pci_bus_id = atoi(optarg);
-			break;
-		case 'd':
-			sscanf(optarg, "%x", &pci_device_id);
-			break;
-		case 'p':
-			display_devices = 1;
-			break;
-		case 'r':
-			open_render_node = 1;
-			break;
-		case 'f':
-			force_run = 1;
-			break;
-		case '?':
 		case 'h':
 			fprintf(stderr, usage, argv[0]);
 			exit(EXIT_SUCCESS);
-		default:
-			fprintf(stderr, usage, argv[0]);
-			exit(EXIT_FAILURE);
 		}
 	}
 
+	for (i = 0; i < MAX_CARDS_SUPPORTED; i++)
+		drm_amdgpu[i] = -1;
+
 	if (amdgpu_open_devices(open_render_node) <= 0) {
 		perror("Cannot open AMDGPU device");
 		exit(EXIT_FAILURE);
@@ -709,12 +752,37 @@ int main(int argc, char **argv)
 		exit(EXIT_FAILURE);
 	}
 
+	/* Parse command line string */
+	opterr = 0;		/* Do not print error messages from getopt */
+	optind = 1;
+	while ((c = getopt(argc, argv, options)) != -1) {
+		switch (c) {
+		case 'p':
+			display_devices = 1;
+			break;
+		}
+	}
+
 	if (display_devices) {
 		amdgpu_print_devices();
 		amdgpu_close_devices();
 		exit(EXIT_SUCCESS);
 	}
 
+	/* Parse command line string */
+	opterr = 0;		/* Do not print error messages from getopt */
+	optind = 1;
+	while ((c = getopt(argc, argv, options)) != -1) {
+		switch (c) {
+		case 'b':
+			pci_bus_id = atoi(optarg);
+			break;
+		case 'd':
+			sscanf(optarg, "%x", &pci_device_id);
+			break;
+		}
+	}
+
 	if (pci_bus_id > 0 || pci_device_id) {
 		/* A device was specified to run the test */
 		test_device_index = amdgpu_find_device(pci_bus_id,
@@ -757,11 +825,85 @@ int main(int argc, char **argv)
 	/* Disable suites and individual tests based on misc. conditions */
 	amdgpu_disable_suites();
 
+	/* Parse command line string */
+	opterr = 0;		/* Do not print error messages from getopt */
+	optind = 1;
+	while ((c = getopt(argc, argv, options)) != -1) {
+		switch (c) {
+		case 'l':
+			display_list = 1;
+			break;
+		}
+	}
+
 	if (display_list) {
 		display_test_suites();
 		goto end;
 	}
 
+	/* Parse command line string */
+	opterr = 0;		/* Do not print error messages from getopt */
+	optind = 1;
+	while ((c = getopt(argc, argv, options)) != -1) {
+		long esuite = -1;
+		long etest = -1;
+		char *endp;
+		switch (c) {
+		case 's':
+			suite_id = atoi(optarg);
+			break;
+		case 't':
+			test_id = atoi(optarg);
+			break;
+		case 'r':
+                       open_render_node = 1;
+                       break;
+		case 'f':
+			force_run = 1;
+			break;
+		case 'e':
+			esuite = strtol(optarg, &endp, 0);
+			if (endp == optarg) {
+				fprintf(stderr, "No digits given for -e argument\n");
+				goto end;
+			} else if (endp && *endp == '.' && esuite > 0) {
+				char *tt = endp + 1;
+				etest = strtol(tt, &endp, 0);
+				if (endp == tt) {
+					fprintf(stderr, "No digits given for test in -e s.t argument\n");
+					goto end;
+				} else if (endp && *endp != '\0') {
+					fprintf(stderr, "Bad input given for test in -e s.t argument\n");
+					goto end;
+				} else if (etest < 1) {
+					fprintf(stderr, "Test in -e s.t argument cannot be smaller than 1\n");
+					goto end;
+				}
+			} else if (endp && *endp != '\0') {
+				fprintf(stderr, "Bad input given for suite for -e s argument\n");
+				goto end;
+			} else if (esuite < 1) {
+				fprintf(stderr, "Suite in -e s argument cannot be smaller than 1\n");
+				goto end;
+			}
+			amdgpu_test_disable(esuite, etest);
+			break;
+		case 'h':
+		case 'p':
+		case 'b':
+		case 'd':
+		case 'l':
+			/* Those have been processed earlier.
+			 */
+			break;
+		case '?':
+		default:
+			fprintf(stderr, "Unknown command line option '%c'. Try -h.\n",
+				c == '?' ? optopt : c);
+			goto end;
+		}
+	}
+
 	if (suite_id != -1) {	/* If user specify particular suite? */
 		pSuite = CU_get_suite_by_index((unsigned int) suite_id,
 						CU_get_registry());
diff --git a/tests/amdgpu/amdgpu_test.h b/tests/amdgpu/amdgpu_test.h
index 2c43a2fa..e2ba043b 100644
--- a/tests/amdgpu/amdgpu_test.h
+++ b/tests/amdgpu/amdgpu_test.h
@@ -261,11 +261,26 @@ CU_BOOL suite_syncobj_timeline_tests_enable(void);
  */
 extern CU_TestInfo syncobj_timeline_tests[];
 
-void amdgpu_dispatch_hang_helper(amdgpu_device_handle device_handle, uint32_t ip_type);
-void amdgpu_dispatch_hang_slow_helper(amdgpu_device_handle device_handle, uint32_t ip_type);
-void amdgpu_memcpy_draw_test(amdgpu_device_handle device_handle, uint32_t ring,
-			     int hang);
-void amdgpu_memcpy_draw_hang_slow_test(amdgpu_device_handle device_handle, uint32_t ring);
+
+/**
+ * Initialize cp dma test suite
+ */
+int suite_cp_dma_tests_init();
+
+/**
+ * Deinitialize cp dma test suite
+ */
+int suite_cp_dma_tests_clean();
+
+/**
+ * Decide if the suite is enabled by default or not.
+ */
+CU_BOOL suite_cp_dma_tests_enable(void);
+
+/**
+ * Tests in cp dma test suite
+ */
+extern CU_TestInfo cp_dma_tests[];
 
 /**
  * Initialize security test suite
@@ -293,7 +308,12 @@ amdgpu_command_submission_write_linear_helper_with_secure(amdgpu_device_handle
 							  unsigned ip_type,
 							  bool secure);
 
-
+extern void amdgpu_test_dispatch_helper(amdgpu_device_handle device_handle, unsigned ip);
+extern void amdgpu_test_dispatch_hang_helper(amdgpu_device_handle device_handle, uint32_t ip);
+extern void amdgpu_test_dispatch_hang_slow_helper(amdgpu_device_handle device_handle, uint32_t ip);
+extern void amdgpu_test_draw_helper(amdgpu_device_handle device_handle);
+extern void amdgpu_test_draw_hang_helper(amdgpu_device_handle device_handle);
+extern void amdgpu_test_draw_hang_slow_helper(amdgpu_device_handle device_handle);
 
 /**
  * Initialize hotunplug test suite
diff --git a/tests/amdgpu/basic_tests.c b/tests/amdgpu/basic_tests.c
index 8afd05c1..0e4a357b 100644
--- a/tests/amdgpu/basic_tests.c
+++ b/tests/amdgpu/basic_tests.c
@@ -292,6 +292,8 @@ CU_TestInfo basic_tests[] = {
 #define PKT3_SET_SH_REG                        0x76
 #define		PACKET3_SET_SH_REG_START			0x00002c00
 
+#define PKT3_SET_SH_REG_INDEX			0x9B
+
 #define	PACKET3_DISPATCH_DIRECT				0x15
 #define PACKET3_EVENT_WRITE				0x46
 #define PACKET3_ACQUIRE_MEM				0x58
@@ -351,6 +353,12 @@ static const uint32_t bufferclear_cs_shader_gfx9[] = {
     0xbf810000
 };
 
+static const uint32_t bufferclear_cs_shader_gfx10[] = {
+	0xD7460004, 0x04010C08, 0x7E000204, 0x7E020205,
+	0x7E040206, 0x7E060207, 0xE01C2000, 0x80000004,
+	0xBF810000
+};
+
 static const uint32_t bufferclear_cs_shader_registers_gfx9[][2] = {
 	{0x2e12, 0x000C0041},	//{ mmCOMPUTE_PGM_RSRC1,	  0x000C0041 },
 	{0x2e13, 0x00000090},	//{ mmCOMPUTE_PGM_RSRC2,	  0x00000090 },
@@ -367,6 +375,11 @@ static const uint32_t buffercopy_cs_shader_gfx9[] = {
     0xe01c2000, 0x80010200, 0xbf810000
 };
 
+static const uint32_t buffercopy_cs_shader_gfx10[] = {
+	0xD7460001, 0x04010C08, 0xE00C2000, 0x80000201,
+	0xBF8C3F70, 0xE01C2000, 0x80010201, 0xBF810000
+};
+
 static const uint32_t preamblecache_gfx9[] = {
 	0xc0026900, 0x81, 0x80000000, 0x40004000, 0xc0026900, 0x8c, 0xaa99aaaa, 0x0,
 	0xc0026900, 0x90, 0x80000000, 0x40004000, 0xc0026900, 0x94, 0x80000000, 0x40004000,
@@ -390,6 +403,32 @@ static const uint32_t preamblecache_gfx9[] = {
 	0xc0017900, 0x24b, 0x0
 };
 
+static const uint32_t preamblecache_gfx10[] = {
+	0xc0026900, 0x81, 0x80000000, 0x40004000, 0xc0026900, 0x8c, 0xaa99aaaa, 0x0,
+	0xc0026900, 0x90, 0x80000000, 0x40004000, 0xc0026900, 0x94, 0x80000000, 0x40004000,
+	0xc0026900, 0xb4, 0x0, 0x3f800000, 0xc0016900, 0x103, 0x0,
+	0xc0016900, 0x208, 0x0, 0xc0016900, 0x290, 0x0,
+	0xc0016900, 0x2a1, 0x0, 0xc0026900, 0x2ad, 0x0, 0x0,
+	0xc0016900, 0x2d5, 0x10000, 0xc0016900, 0x2dc, 0x0,
+	0xc0066900, 0x2de, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0026900, 0x2e5, 0x0, 0x0,
+	0xc0056900, 0x2f9, 0x5, 0x3f800000, 0x3f800000, 0x3f800000, 0x3f800000,
+	0xc0046900, 0x310, 0, 0x3, 0, 0x100000, 0xc0026900, 0x316, 0xe, 0x20,
+	0xc0016900, 0x349, 0x0, 0xc0016900, 0x358, 0x0, 0xc0016900, 0x367, 0x0,
+	0xc0016900, 0x376, 0x0, 0xc0016900, 0x385, 0x0, 0xc0016900, 0x6, 0x0,
+	0xc0056900, 0xe8, 0x0, 0x0, 0x0, 0x0, 0x0,
+	0xc0076900, 0x1e1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
+	0xc0026900, 0x204, 0x90000, 0x4, 0xc0046900, 0x20c, 0x0, 0x0, 0x0, 0x0,
+	0xc0016900, 0x2b2, 0x0, 0xc0026900, 0x30e, 0xffffffff, 0xffffffff,
+	0xc0016900, 0x314, 0x0, 0xc0016900, 0x10a, 0, 0xc0016900, 0x2a6, 0, 0xc0016900, 0x210, 0,
+	0xc0016900, 0x2db, 0, 0xc0016900, 0x1d4, 0, 0xc0002f00, 0x1, 0xc0016900, 0x1, 0x1, 0xc0016900, 0xe, 0x2,
+	0xc0016900, 0x206, 0x300, 0xc0016900, 0x212, 0x200, 0xc0017900, 0x7b, 0x20, 0xc0017a00, 0x20000243, 0x0,
+	0xc0017900, 0x249, 0, 0xc0017900, 0x24a, 0, 0xc0017900, 0x24b, 0, 0xc0017900, 0x259, 0xffffffff,
+	0xc0017900, 0x25f, 0, 0xc0017900, 0x260, 0, 0xc0017900, 0x262, 0,
+	0xc0017600, 0x45, 0x0, 0xc0017600, 0x6, 0x0,
+	0xc0067600, 0x70, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
+	0xc0067600, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
+};
+
 enum ps_type {
 	PS_CONST,
 	PS_TEX,
@@ -442,6 +481,39 @@ static const uint32_t ps_const_context_reg_gfx9[][2] = {
     {0xA1C5, 0x00000004}, //{ mmSPI_SHADER_COL_FORMAT,   0x00000004 }
 };
 
+static const uint32_t ps_const_shader_gfx10[] = {
+    0x7E000200, 0x7E020201, 0x7E040202, 0x7E060203,
+    0x5E000300, 0x5E020702, 0xBF800000, 0xBF800000,
+    0xF8001C0F, 0x00000100, 0xBF810000
+};
+
+static const uint32_t ps_const_shader_patchinfo_code_size_gfx10 = 6;
+
+static const uint32_t ps_const_shader_patchinfo_code_gfx10[][10][6] = {
+    {{ 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001890, 0x00000000 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001801, 0x00000000 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001803, 0x00000100 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001803, 0x00000300 },
+     { 0x5E000300, 0x5E020702, 0xBF800000, 0xBF800000, 0xF8001C0F, 0x00000100 },
+     { 0xD7690000, 0x00020300, 0xD7690001, 0x00020702, 0xF8001C0F, 0x00000100 },
+     { 0xD7680000, 0x00020300, 0xD7680001, 0x00020702, 0xF8001C0F, 0x00000100 },
+     { 0xD76A0000, 0x00020300, 0xD76A0001, 0x00020702, 0xF8001C0F, 0x00000100 },
+     { 0xD76B0000, 0x00020300, 0xD76B0001, 0x00020702, 0xF8001C0F, 0x00000100 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF800180F, 0x03020100 }
+    }
+};
+
+static const uint32_t ps_const_shader_patchinfo_offset_gfx10[] = {
+    0x00000004
+};
+
+static const uint32_t ps_num_sh_registers_gfx10 = 2;
+
+static const uint32_t ps_const_sh_registers_gfx10[][2] = {
+    {0x2C0A, 0x000C0000},//{ mmSPI_SHADER_PGM_RSRC1_PS, 0x000C0000 },
+    {0x2C0B, 0x00000008}, //{ mmSPI_SHADER_PGM_RSRC2_PS, 0x00000008 }
+};
+
 static const uint32_t ps_tex_shader_gfx9[] = {
     0xBEFC000C, 0xBE8E017E, 0xBEFE077E, 0xD4180000,
     0xD4190001, 0xD41C0100, 0xD41D0101, 0xF0800F00,
@@ -485,6 +557,34 @@ static const uint32_t ps_tex_context_reg_gfx9[][2] = {
     {0xA1C5, 0x00000004}, //{ mmSPI_SHADER_COL_FORMAT,   0x00000004  }
 };
 
+static const uint32_t ps_tex_shader_gfx10[] = {
+    0xBEFC030C, 0xBE8E047E, 0xBEFE0A7E, 0xC8080000,
+    0xC80C0100, 0xC8090001, 0xC80D0101, 0xF0800F0A,
+    0x00400402, 0x00000003, 0xBEFE040E, 0xBF8C0F70,
+    0x5E000B04, 0x5E020F06, 0xBF800000, 0xBF800000,
+    0xF8001C0F, 0x00000100, 0xBF810000
+};
+
+static const uint32_t ps_tex_shader_patchinfo_offset_gfx10[] = {
+    0x0000000C
+};
+
+static const uint32_t ps_tex_shader_patchinfo_code_size_gfx10 = 6;
+
+static const uint32_t ps_tex_shader_patchinfo_code_gfx10[][10][6] = {
+    {{ 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001890, 0x00000000 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001801, 0x00000004 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001803, 0x00000504 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001803, 0x00000704 },
+     { 0x5E000B04, 0x5E020F06, 0xBF800000, 0xBF800000, 0xF8001C0F, 0x00000100 },
+     { 0xD7690000, 0x00020B04, 0xD7690001, 0x00020F06, 0xF8001C0F, 0x00000100 },
+     { 0xD7680000, 0x00020B04, 0xD7680001, 0x00020F06, 0xF8001C0F, 0x00000100 },
+     { 0xD76A0000, 0x00020B04, 0xD76A0001, 0x00020F06, 0xF8001C0F, 0x00000100 },
+     { 0xD76B0000, 0x00020B04, 0xD76B0001, 0x00020F06, 0xF8001C0F, 0x00000100 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF800180F, 0x07060504 }
+    }
+};
+
 static const uint32_t vs_RectPosTexFast_shader_gfx9[] = {
     0x7E000B00, 0x020000F3, 0xD042000A, 0x00010100,
     0x7E020202, 0x7E040200, 0x020000F3, 0x7E060206,
@@ -496,6 +596,17 @@ static const uint32_t vs_RectPosTexFast_shader_gfx9[] = {
     0xC400020F, 0x05060403, 0xBF810000
 };
 
+static const uint32_t vs_RectPosTexFast_shader_gfx10[] = {
+    0x7E000B00, 0x060000F3, 0x7E020202, 0x7E040206,
+    0x7C040080, 0x060000F3, 0xD5010001, 0x01AA0200,
+    0x7E060203, 0xD5010002, 0x01AA0404, 0x7E080207,
+    0x7C040080, 0xD5010000, 0x01A80101, 0xD5010001,
+    0x01AA0601, 0x7E060208, 0x7E0A02F2, 0xD5010002,
+    0x01A80902, 0xD5010004, 0x01AA0805, 0x7E0C0209,
+    0xF80008CF, 0x05030100, 0xF800020F, 0x05060402,
+    0xBF810000
+};
+
 static const uint32_t cached_cmd_gfx9[] = {
 	0xc0016900, 0x0, 0x0, 0xc0026900, 0x3, 0x2a, 0x0,
 	0xc0046900, 0xa, 0x0, 0x0, 0x0, 0x200020,
@@ -507,6 +618,17 @@ static const uint32_t cached_cmd_gfx9[] = {
 	0xc0026900, 0x2b0, 0x0, 0x0, 0xc0016900, 0x2f8, 0x0
 };
 
+static const uint32_t cached_cmd_gfx10[] = {
+	0xc0016900, 0x0, 0x0, 0xc0026900, 0x3, 0x2a, 0x0,
+	0xc0046900, 0xa, 0x0, 0x0, 0x0, 0x200020,
+	0xc0016900, 0x83, 0xffff, 0xc0026900, 0x8e, 0xf, 0xf,
+	0xc0056900, 0x105, 0x0, 0x0, 0x0, 0x0, 0x18,
+	0xc0026900, 0x10b, 0x0, 0x0, 0xc0016900, 0x1e0, 0x0,
+	0xc0036900, 0x200, 0x0, 0x10000, 0xcc0011,
+	0xc0026900, 0x292, 0x20, 0x6020000,
+	0xc0026900, 0x2b0, 0x0, 0x0, 0xc0016900, 0x2f8, 0x0
+};
+
 unsigned int memcpy_ps_hang[] = {
         0xFFFFFFFF, 0xBEFE0A7E, 0xBEFC0304, 0xC0C20100,
         0xC0800300, 0xC8080000, 0xC80C0100, 0xC8090001,
@@ -546,6 +668,18 @@ struct amdgpu_test_shader memcpy_cs_hang_slow_rv = {
         1
 };
 
+unsigned int memcpy_cs_hang_slow_nv_codes[] = {
+    0xd7460000, 0x04010c08, 0xe00c2000, 0x80000100,
+    0xbf8c0f70, 0xe01ca000, 0x80010100, 0xbf810000
+};
+
+struct amdgpu_test_shader memcpy_cs_hang_slow_nv = {
+        memcpy_cs_hang_slow_nv_codes,
+        4,
+        3,
+        1
+};
+
 unsigned int memcpy_ps_hang_slow_ai_codes[] = {
         0xbefc000c, 0xbe8e017e, 0xbefe077e, 0xd4080000,
         0xd4090001, 0xd40c0100, 0xd40d0101, 0xf0800f00,
@@ -723,6 +857,13 @@ static void amdgpu_command_submission_gfx_separate_ibs(void)
 	amdgpu_bo_list_handle bo_list;
 	amdgpu_va_handle va_handle, va_handle_ce;
 	int r, i = 0;
+	struct drm_amdgpu_info_hw_ip info;
+
+	r = amdgpu_query_hw_ip_info(device_handle, AMDGPU_HW_IP_GFX, 0, &info);
+	CU_ASSERT_EQUAL(r, 0);
+
+	if (info.hw_ip_version_major >= 11)
+		return;
 
 	r = amdgpu_cs_ctx_create(device_handle, &context_handle);
 	CU_ASSERT_EQUAL(r, 0);
@@ -814,6 +955,13 @@ static void amdgpu_command_submission_gfx_shared_ib(void)
 	amdgpu_bo_list_handle bo_list;
 	amdgpu_va_handle va_handle;
 	int r, i = 0;
+	struct drm_amdgpu_info_hw_ip info;
+
+	r = amdgpu_query_hw_ip_info(device_handle, AMDGPU_HW_IP_GFX, 0, &info);
+	CU_ASSERT_EQUAL(r, 0);
+
+	if (info.hw_ip_version_major >= 11)
+		return;
 
 	r = amdgpu_cs_ctx_create(device_handle, &context_handle);
 	CU_ASSERT_EQUAL(r, 0);
@@ -1145,7 +1293,7 @@ static void amdgpu_semaphore_test(void)
 	fence_status.ip_instance = 0;
 	fence_status.fence = ibs_request[1].seq_no;
 	r = amdgpu_cs_query_fence_status(&fence_status,
-					 500000000, 0, &expired);
+					 AMDGPU_TIMEOUT_INFINITE, 0, &expired);
 	CU_ASSERT_EQUAL(r, 0);
 	CU_ASSERT_EQUAL(expired, true);
 
@@ -1186,7 +1334,7 @@ static void amdgpu_semaphore_test(void)
 	fence_status.ip_instance = 0;
 	fence_status.fence = ibs_request[1].seq_no;
 	r = amdgpu_cs_query_fence_status(&fence_status,
-					 500000000, 0, &expired);
+					 AMDGPU_TIMEOUT_INFINITE, 0, &expired);
 	CU_ASSERT_EQUAL(r, 0);
 	CU_ASSERT_EQUAL(expired, true);
 
@@ -1936,6 +2084,13 @@ static void amdgpu_command_submission_multi_fence_wait_all(bool wait_all)
 	amdgpu_va_handle va_handle, va_handle_ce;
 	int r;
 	int i = 0, ib_cs_num = 2;
+	struct drm_amdgpu_info_hw_ip info;
+
+	r = amdgpu_query_hw_ip_info(device_handle, AMDGPU_HW_IP_GFX, 0, &info);
+	CU_ASSERT_EQUAL(r, 0);
+
+	if (info.hw_ip_version_major >= 11)
+		return;
 
 	r = amdgpu_cs_ctx_create(device_handle, &context_handle);
 	CU_ASSERT_EQUAL(r, 0);
@@ -2323,1533 +2478,19 @@ static void amdgpu_sync_dependency_test(void)
 	free(ibs_request.dependencies);
 }
 
-static int amdgpu_dispatch_load_cs_shader_hang_slow(uint32_t *ptr, int family)
-{
-	struct amdgpu_test_shader *shader;
-	int i, loop = 0x10000;
-
-	switch (family) {
-		case AMDGPU_FAMILY_AI:
-			shader = &memcpy_cs_hang_slow_ai;
-			break;
-		case AMDGPU_FAMILY_RV:
-			shader = &memcpy_cs_hang_slow_rv;
-			break;
-		default:
-			return -1;
-			break;
-	}
-
-	memcpy(ptr, shader->shader, shader->header_length * sizeof(uint32_t));
-
-	for (i = 0; i < loop; i++)
-		memcpy(ptr + shader->header_length + shader->body_length * i,
-			shader->shader + shader->header_length,
-			shader->body_length * sizeof(uint32_t));
-
-	memcpy(ptr + shader->header_length + shader->body_length * loop,
-		shader->shader + shader->header_length + shader->body_length,
-		shader->foot_length * sizeof(uint32_t));
-
-	return 0;
-}
-
-static int amdgpu_dispatch_load_cs_shader(uint8_t *ptr,
-					   int cs_type)
-{
-	uint32_t shader_size;
-	const uint32_t *shader;
-
-	switch (cs_type) {
-		case CS_BUFFERCLEAR:
-			shader = bufferclear_cs_shader_gfx9;
-			shader_size = sizeof(bufferclear_cs_shader_gfx9);
-			break;
-		case CS_BUFFERCOPY:
-			shader = buffercopy_cs_shader_gfx9;
-			shader_size = sizeof(buffercopy_cs_shader_gfx9);
-			break;
-		case CS_HANG:
-			shader = memcpy_ps_hang;
-			shader_size = sizeof(memcpy_ps_hang);
-			break;
-		default:
-			return -1;
-			break;
-	}
-
-	memcpy(ptr, shader, shader_size);
-	return 0;
-}
-
-static int amdgpu_dispatch_init(uint32_t *ptr, uint32_t ip_type)
-{
-	int i = 0;
-
-	/* Write context control and load shadowing register if necessary */
-	if (ip_type == AMDGPU_HW_IP_GFX) {
-		ptr[i++] = PACKET3(PKT3_CONTEXT_CONTROL, 1);
-		ptr[i++] = 0x80000000;
-		ptr[i++] = 0x80000000;
-	}
-
-	/* Issue commands to set default compute state. */
-	/* clear mmCOMPUTE_START_Z - mmCOMPUTE_START_X */
-	ptr[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 3);
-	ptr[i++] = 0x204;
-	i += 3;
-
-	/* clear mmCOMPUTE_TMPRING_SIZE */
-	ptr[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 1);
-	ptr[i++] = 0x218;
-	ptr[i++] = 0;
-
-	return i;
-}
-
-static int amdgpu_dispatch_write_cumask(uint32_t *ptr)
-{
-	int i = 0;
-
-	/*  Issue commands to set cu mask used in current dispatch */
-	/* set mmCOMPUTE_STATIC_THREAD_MGMT_SE1 - mmCOMPUTE_STATIC_THREAD_MGMT_SE0 */
-	ptr[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 2);
-	ptr[i++] = 0x216;
-	ptr[i++] = 0xffffffff;
-	ptr[i++] = 0xffffffff;
-	/* set mmCOMPUTE_STATIC_THREAD_MGMT_SE3 - mmCOMPUTE_STATIC_THREAD_MGMT_SE2 */
-	ptr[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 2);
-	ptr[i++] = 0x219;
-	ptr[i++] = 0xffffffff;
-	ptr[i++] = 0xffffffff;
-
-	return i;
-}
-
-static int amdgpu_dispatch_write2hw(uint32_t *ptr, uint64_t shader_addr)
-{
-	int i, j;
-
-	i = 0;
-
-	/* Writes shader state to HW */
-	/* set mmCOMPUTE_PGM_HI - mmCOMPUTE_PGM_LO */
-	ptr[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 2);
-	ptr[i++] = 0x20c;
-	ptr[i++] = (shader_addr >> 8);
-	ptr[i++] = (shader_addr >> 40);
-	/* write sh regs*/
-	for (j = 0; j < bufferclear_cs_shader_registers_num_gfx9; j++) {
-		ptr[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 1);
-		/* - Gfx9ShRegBase */
-		ptr[i++] = bufferclear_cs_shader_registers_gfx9[j][0] - 0x2c00;
-		ptr[i++] = bufferclear_cs_shader_registers_gfx9[j][1];
-	}
-
-	return i;
-}
-
-static void amdgpu_memset_dispatch_test(amdgpu_device_handle device_handle,
-					 uint32_t ip_type,
-					 uint32_t ring)
-{
-	amdgpu_context_handle context_handle;
-	amdgpu_bo_handle bo_dst, bo_shader, bo_cmd, resources[3];
-	volatile unsigned char *ptr_dst;
-	void *ptr_shader;
-	uint32_t *ptr_cmd;
-	uint64_t mc_address_dst, mc_address_shader, mc_address_cmd;
-	amdgpu_va_handle va_dst, va_shader, va_cmd;
-	int i, r;
-	int bo_dst_size = 16384;
-	int bo_shader_size = 4096;
-	int bo_cmd_size = 4096;
-	struct amdgpu_cs_request ibs_request = {0};
-	struct amdgpu_cs_ib_info ib_info= {0};
-	amdgpu_bo_list_handle bo_list;
-	struct amdgpu_cs_fence fence_status = {0};
-	uint32_t expired;
-
-	r = amdgpu_cs_ctx_create(device_handle, &context_handle);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_cmd_size, 4096,
-					AMDGPU_GEM_DOMAIN_GTT, 0,
-					&bo_cmd, (void **)&ptr_cmd,
-					&mc_address_cmd, &va_cmd);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_cmd, 0, bo_cmd_size);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_shader_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_shader, &ptr_shader,
-					&mc_address_shader, &va_shader);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_shader, 0, bo_shader_size);
-
-	r = amdgpu_dispatch_load_cs_shader(ptr_shader, CS_BUFFERCLEAR);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_dst_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_dst, (void **)&ptr_dst,
-					&mc_address_dst, &va_dst);
-	CU_ASSERT_EQUAL(r, 0);
-
-	i = 0;
-	i += amdgpu_dispatch_init(ptr_cmd + i, ip_type);
-
-	/*  Issue commands to set cu mask used in current dispatch */
-	i += amdgpu_dispatch_write_cumask(ptr_cmd + i);
-
-	/* Writes shader state to HW */
-	i += amdgpu_dispatch_write2hw(ptr_cmd + i, mc_address_shader);
-
-	/* Write constant data */
-	/* Writes the UAV constant data to the SGPRs. */
-	ptr_cmd[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 4);
-	ptr_cmd[i++] = 0x240;
-	ptr_cmd[i++] = mc_address_dst;
-	ptr_cmd[i++] = (mc_address_dst >> 32) | 0x100000;
-	ptr_cmd[i++] = 0x400;
-	ptr_cmd[i++] = 0x74fac;
-
-	/* Sets a range of pixel shader constants */
-	ptr_cmd[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 4);
-	ptr_cmd[i++] = 0x244;
-	ptr_cmd[i++] = 0x22222222;
-	ptr_cmd[i++] = 0x22222222;
-	ptr_cmd[i++] = 0x22222222;
-	ptr_cmd[i++] = 0x22222222;
-
-	/* clear mmCOMPUTE_RESOURCE_LIMITS */
-	ptr_cmd[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 1);
-	ptr_cmd[i++] = 0x215;
-	ptr_cmd[i++] = 0;
-
-	/* dispatch direct command */
-	ptr_cmd[i++] = PACKET3_COMPUTE(PACKET3_DISPATCH_DIRECT, 3);
-	ptr_cmd[i++] = 0x10;
-	ptr_cmd[i++] = 1;
-	ptr_cmd[i++] = 1;
-	ptr_cmd[i++] = 1;
-
-	while (i & 7)
-		ptr_cmd[i++] = 0xffff1000; /* type3 nop packet */
-
-	resources[0] = bo_dst;
-	resources[1] = bo_shader;
-	resources[2] = bo_cmd;
-	r = amdgpu_bo_list_create(device_handle, 3, resources, NULL, &bo_list);
-	CU_ASSERT_EQUAL(r, 0);
-
-	ib_info.ib_mc_address = mc_address_cmd;
-	ib_info.size = i;
-	ibs_request.ip_type = ip_type;
-	ibs_request.ring = ring;
-	ibs_request.resources = bo_list;
-	ibs_request.number_of_ibs = 1;
-	ibs_request.ibs = &ib_info;
-	ibs_request.fence_info.handle = NULL;
-
-	/* submit CS */
-	r = amdgpu_cs_submit(context_handle, 0, &ibs_request, 1);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_list_destroy(bo_list);
-	CU_ASSERT_EQUAL(r, 0);
-
-	fence_status.ip_type = ip_type;
-	fence_status.ip_instance = 0;
-	fence_status.ring = ring;
-	fence_status.context = context_handle;
-	fence_status.fence = ibs_request.seq_no;
-
-	/* wait for IB accomplished */
-	r = amdgpu_cs_query_fence_status(&fence_status,
-					 AMDGPU_TIMEOUT_INFINITE,
-					 0, &expired);
-	CU_ASSERT_EQUAL(r, 0);
-	CU_ASSERT_EQUAL(expired, true);
-
-	/* verify if memset test result meets with expected */
-	i = 0;
-	while(i < bo_dst_size) {
-		CU_ASSERT_EQUAL(ptr_dst[i++], 0x22);
-	}
-
-	r = amdgpu_bo_unmap_and_free(bo_dst, va_dst, mc_address_dst, bo_dst_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_shader, va_shader, mc_address_shader, bo_shader_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_cmd, va_cmd, mc_address_cmd, bo_cmd_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_cs_ctx_free(context_handle);
-	CU_ASSERT_EQUAL(r, 0);
-}
-
-static void amdgpu_memcpy_dispatch_test(amdgpu_device_handle device_handle,
-					uint32_t ip_type,
-					uint32_t ring,
-					int hang)
-{
-	amdgpu_context_handle context_handle;
-	amdgpu_bo_handle bo_src, bo_dst, bo_shader, bo_cmd, resources[4];
-	volatile unsigned char *ptr_dst;
-	void *ptr_shader;
-	unsigned char *ptr_src;
-	uint32_t *ptr_cmd;
-	uint64_t mc_address_src, mc_address_dst, mc_address_shader, mc_address_cmd;
-	amdgpu_va_handle va_src, va_dst, va_shader, va_cmd;
-	int i, r;
-	int bo_dst_size = 16384;
-	int bo_shader_size = 4096;
-	int bo_cmd_size = 4096;
-	struct amdgpu_cs_request ibs_request = {0};
-	struct amdgpu_cs_ib_info ib_info= {0};
-	uint32_t expired, hang_state, hangs;
-	enum cs_type cs_type;
-	amdgpu_bo_list_handle bo_list;
-	struct amdgpu_cs_fence fence_status = {0};
-
-	r = amdgpu_cs_ctx_create(device_handle, &context_handle);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_cmd_size, 4096,
-				    AMDGPU_GEM_DOMAIN_GTT, 0,
-				    &bo_cmd, (void **)&ptr_cmd,
-				    &mc_address_cmd, &va_cmd);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_cmd, 0, bo_cmd_size);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_shader_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_shader, &ptr_shader,
-					&mc_address_shader, &va_shader);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_shader, 0, bo_shader_size);
-
-	cs_type = hang ? CS_HANG : CS_BUFFERCOPY;
-	r = amdgpu_dispatch_load_cs_shader(ptr_shader, cs_type);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_dst_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_src, (void **)&ptr_src,
-					&mc_address_src, &va_src);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_dst_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_dst, (void **)&ptr_dst,
-					&mc_address_dst, &va_dst);
-	CU_ASSERT_EQUAL(r, 0);
-
-	memset(ptr_src, 0x55, bo_dst_size);
-
-	i = 0;
-	i += amdgpu_dispatch_init(ptr_cmd + i, ip_type);
-
-	/*  Issue commands to set cu mask used in current dispatch */
-	i += amdgpu_dispatch_write_cumask(ptr_cmd + i);
-
-	/* Writes shader state to HW */
-	i += amdgpu_dispatch_write2hw(ptr_cmd + i, mc_address_shader);
-
-	/* Write constant data */
-	/* Writes the texture resource constants data to the SGPRs */
-	ptr_cmd[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 4);
-	ptr_cmd[i++] = 0x240;
-	ptr_cmd[i++] = mc_address_src;
-	ptr_cmd[i++] = (mc_address_src >> 32) | 0x100000;
-	ptr_cmd[i++] = 0x400;
-	ptr_cmd[i++] = 0x74fac;
-
-	/* Writes the UAV constant data to the SGPRs. */
-	ptr_cmd[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 4);
-	ptr_cmd[i++] = 0x244;
-	ptr_cmd[i++] = mc_address_dst;
-	ptr_cmd[i++] = (mc_address_dst >> 32) | 0x100000;
-	ptr_cmd[i++] = 0x400;
-	ptr_cmd[i++] = 0x74fac;
-
-	/* clear mmCOMPUTE_RESOURCE_LIMITS */
-	ptr_cmd[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 1);
-	ptr_cmd[i++] = 0x215;
-	ptr_cmd[i++] = 0;
-
-	/* dispatch direct command */
-	ptr_cmd[i++] = PACKET3_COMPUTE(PACKET3_DISPATCH_DIRECT, 3);
-	ptr_cmd[i++] = 0x10;
-	ptr_cmd[i++] = 1;
-	ptr_cmd[i++] = 1;
-	ptr_cmd[i++] = 1;
-
-	while (i & 7)
-		ptr_cmd[i++] = 0xffff1000; /* type3 nop packet */
-
-	resources[0] = bo_shader;
-	resources[1] = bo_src;
-	resources[2] = bo_dst;
-	resources[3] = bo_cmd;
-	r = amdgpu_bo_list_create(device_handle, 4, resources, NULL, &bo_list);
-	CU_ASSERT_EQUAL(r, 0);
-
-	ib_info.ib_mc_address = mc_address_cmd;
-	ib_info.size = i;
-	ibs_request.ip_type = ip_type;
-	ibs_request.ring = ring;
-	ibs_request.resources = bo_list;
-	ibs_request.number_of_ibs = 1;
-	ibs_request.ibs = &ib_info;
-	ibs_request.fence_info.handle = NULL;
-	r = amdgpu_cs_submit(context_handle, 0, &ibs_request, 1);
-	CU_ASSERT_EQUAL(r, 0);
-
-	fence_status.ip_type = ip_type;
-	fence_status.ip_instance = 0;
-	fence_status.ring = ring;
-	fence_status.context = context_handle;
-	fence_status.fence = ibs_request.seq_no;
-
-	/* wait for IB accomplished */
-	r = amdgpu_cs_query_fence_status(&fence_status,
-					 AMDGPU_TIMEOUT_INFINITE,
-					 0, &expired);
-
-	if (!hang) {
-		CU_ASSERT_EQUAL(r, 0);
-		CU_ASSERT_EQUAL(expired, true);
-
-		/* verify if memcpy test result meets with expected */
-		i = 0;
-		while(i < bo_dst_size) {
-			CU_ASSERT_EQUAL(ptr_dst[i], ptr_src[i]);
-			i++;
-		}
-	} else {
-		r = amdgpu_cs_query_reset_state(context_handle, &hang_state, &hangs);
-		CU_ASSERT_EQUAL(r, 0);
-		CU_ASSERT_EQUAL(hang_state, AMDGPU_CTX_UNKNOWN_RESET);
-	}
-
-	r = amdgpu_bo_list_destroy(bo_list);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_src, va_src, mc_address_src, bo_dst_size);
-	CU_ASSERT_EQUAL(r, 0);
-	r = amdgpu_bo_unmap_and_free(bo_dst, va_dst, mc_address_dst, bo_dst_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_cmd, va_cmd, mc_address_cmd, bo_cmd_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_shader, va_shader, mc_address_shader, bo_shader_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_cs_ctx_free(context_handle);
-	CU_ASSERT_EQUAL(r, 0);
-}
-
 static void amdgpu_compute_dispatch_test(void)
 {
-	int r;
-	struct drm_amdgpu_info_hw_ip info;
-	uint32_t ring_id;
-
-	r = amdgpu_query_hw_ip_info(device_handle, AMDGPU_HW_IP_COMPUTE, 0, &info);
-	CU_ASSERT_EQUAL(r, 0);
-	if (!info.available_rings)
-		printf("SKIP ... as there's no compute ring\n");
-
-	for (ring_id = 0; (1 << ring_id) & info.available_rings; ring_id++) {
-		amdgpu_memset_dispatch_test(device_handle, AMDGPU_HW_IP_COMPUTE, ring_id);
-		amdgpu_memcpy_dispatch_test(device_handle, AMDGPU_HW_IP_COMPUTE, ring_id, 0);
-	}
+	amdgpu_test_dispatch_helper(device_handle, AMDGPU_HW_IP_COMPUTE);
 }
-
 static void amdgpu_gfx_dispatch_test(void)
 {
-	int r;
-	struct drm_amdgpu_info_hw_ip info;
-	uint32_t ring_id;
-
-	r = amdgpu_query_hw_ip_info(device_handle, AMDGPU_HW_IP_GFX, 0, &info);
-	CU_ASSERT_EQUAL(r, 0);
-	if (!info.available_rings)
-		printf("SKIP ... as there's no graphics ring\n");
-
-	for (ring_id = 0; (1 << ring_id) & info.available_rings; ring_id++) {
-		amdgpu_memset_dispatch_test(device_handle, AMDGPU_HW_IP_GFX, ring_id);
-		amdgpu_memcpy_dispatch_test(device_handle, AMDGPU_HW_IP_GFX, ring_id, 0);
-	}
+	amdgpu_test_dispatch_helper(device_handle, AMDGPU_HW_IP_GFX);
 }
 
-void amdgpu_dispatch_hang_helper(amdgpu_device_handle device_handle, uint32_t ip_type)
+static void amdgpu_draw_test(void)
 {
-	int r;
-	struct drm_amdgpu_info_hw_ip info;
-	uint32_t ring_id;
-
-	r = amdgpu_query_hw_ip_info(device_handle, ip_type, 0, &info);
-	CU_ASSERT_EQUAL(r, 0);
-	if (!info.available_rings)
-		printf("SKIP ... as there's no ring for ip %d\n", ip_type);
-
-	for (ring_id = 0; (1 << ring_id) & info.available_rings; ring_id++) {
-		amdgpu_memcpy_dispatch_test(device_handle, ip_type, ring_id, 0);
-		amdgpu_memcpy_dispatch_test(device_handle, ip_type, ring_id, 1);
-		amdgpu_memcpy_dispatch_test(device_handle, ip_type, ring_id, 0);
-	}
+	amdgpu_test_draw_helper(device_handle);
 }
-
-static void amdgpu_memcpy_dispatch_hang_slow_test(amdgpu_device_handle device_handle,
-						  uint32_t ip_type, uint32_t ring)
-{
-	amdgpu_context_handle context_handle;
-	amdgpu_bo_handle bo_src, bo_dst, bo_shader, bo_cmd, resources[4];
-	volatile unsigned char *ptr_dst;
-	void *ptr_shader;
-	unsigned char *ptr_src;
-	uint32_t *ptr_cmd;
-	uint64_t mc_address_src, mc_address_dst, mc_address_shader, mc_address_cmd;
-	amdgpu_va_handle va_src, va_dst, va_shader, va_cmd;
-	int i, r;
-	int bo_dst_size = 0x4000000;
-	int bo_shader_size = 0x400000;
-	int bo_cmd_size = 4096;
-	struct amdgpu_cs_request ibs_request = {0};
-	struct amdgpu_cs_ib_info ib_info= {0};
-	uint32_t hang_state, hangs, expired;
-	struct amdgpu_gpu_info gpu_info = {0};
-	amdgpu_bo_list_handle bo_list;
-	struct amdgpu_cs_fence fence_status = {0};
-
-	r = amdgpu_query_gpu_info(device_handle, &gpu_info);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_cs_ctx_create(device_handle, &context_handle);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_cmd_size, 4096,
-				    AMDGPU_GEM_DOMAIN_GTT, 0,
-				    &bo_cmd, (void **)&ptr_cmd,
-				    &mc_address_cmd, &va_cmd);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_cmd, 0, bo_cmd_size);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_shader_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_shader, &ptr_shader,
-					&mc_address_shader, &va_shader);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_shader, 0, bo_shader_size);
-
-	r = amdgpu_dispatch_load_cs_shader_hang_slow(ptr_shader, gpu_info.family_id);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_dst_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_src, (void **)&ptr_src,
-					&mc_address_src, &va_src);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_dst_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_dst, (void **)&ptr_dst,
-					&mc_address_dst, &va_dst);
-	CU_ASSERT_EQUAL(r, 0);
-
-	memset(ptr_src, 0x55, bo_dst_size);
-
-	i = 0;
-	i += amdgpu_dispatch_init(ptr_cmd + i, ip_type);
-
-	/*  Issue commands to set cu mask used in current dispatch */
-	i += amdgpu_dispatch_write_cumask(ptr_cmd + i);
-
-	/* Writes shader state to HW */
-	i += amdgpu_dispatch_write2hw(ptr_cmd + i, mc_address_shader);
-
-	/* Write constant data */
-	/* Writes the texture resource constants data to the SGPRs */
-	ptr_cmd[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 4);
-	ptr_cmd[i++] = 0x240;
-	ptr_cmd[i++] = mc_address_src;
-	ptr_cmd[i++] = (mc_address_src >> 32) | 0x100000;
-	ptr_cmd[i++] = 0x400000;
-	ptr_cmd[i++] = 0x74fac;
-
-	/* Writes the UAV constant data to the SGPRs. */
-	ptr_cmd[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 4);
-	ptr_cmd[i++] = 0x244;
-	ptr_cmd[i++] = mc_address_dst;
-	ptr_cmd[i++] = (mc_address_dst >> 32) | 0x100000;
-	ptr_cmd[i++] = 0x400000;
-	ptr_cmd[i++] = 0x74fac;
-
-	/* clear mmCOMPUTE_RESOURCE_LIMITS */
-	ptr_cmd[i++] = PACKET3_COMPUTE(PKT3_SET_SH_REG, 1);
-	ptr_cmd[i++] = 0x215;
-	ptr_cmd[i++] = 0;
-
-	/* dispatch direct command */
-	ptr_cmd[i++] = PACKET3_COMPUTE(PACKET3_DISPATCH_DIRECT, 3);
-	ptr_cmd[i++] = 0x10000;
-	ptr_cmd[i++] = 1;
-	ptr_cmd[i++] = 1;
-	ptr_cmd[i++] = 1;
-
-	while (i & 7)
-		ptr_cmd[i++] = 0xffff1000; /* type3 nop packet */
-
-	resources[0] = bo_shader;
-	resources[1] = bo_src;
-	resources[2] = bo_dst;
-	resources[3] = bo_cmd;
-	r = amdgpu_bo_list_create(device_handle, 4, resources, NULL, &bo_list);
-	CU_ASSERT_EQUAL(r, 0);
-
-	ib_info.ib_mc_address = mc_address_cmd;
-	ib_info.size = i;
-	ibs_request.ip_type = ip_type;
-	ibs_request.ring = ring;
-	ibs_request.resources = bo_list;
-	ibs_request.number_of_ibs = 1;
-	ibs_request.ibs = &ib_info;
-	ibs_request.fence_info.handle = NULL;
-	r = amdgpu_cs_submit(context_handle, 0, &ibs_request, 1);
-	CU_ASSERT_EQUAL(r, 0);
-
-	fence_status.ip_type = ip_type;
-	fence_status.ip_instance = 0;
-	fence_status.ring = ring;
-	fence_status.context = context_handle;
-	fence_status.fence = ibs_request.seq_no;
-
-	/* wait for IB accomplished */
-	r = amdgpu_cs_query_fence_status(&fence_status,
-					 AMDGPU_TIMEOUT_INFINITE,
-					 0, &expired);
-
-	r = amdgpu_cs_query_reset_state(context_handle, &hang_state, &hangs);
-	CU_ASSERT_EQUAL(r, 0);
-	CU_ASSERT_EQUAL(hang_state, AMDGPU_CTX_UNKNOWN_RESET);
-
-	r = amdgpu_bo_list_destroy(bo_list);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_src, va_src, mc_address_src, bo_dst_size);
-	CU_ASSERT_EQUAL(r, 0);
-	r = amdgpu_bo_unmap_and_free(bo_dst, va_dst, mc_address_dst, bo_dst_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_cmd, va_cmd, mc_address_cmd, bo_cmd_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_shader, va_shader, mc_address_shader, bo_shader_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_cs_ctx_free(context_handle);
-	CU_ASSERT_EQUAL(r, 0);
-}
-
-void amdgpu_dispatch_hang_slow_helper(amdgpu_device_handle device_handle, uint32_t ip_type)
-{
-	int r;
-	struct drm_amdgpu_info_hw_ip info;
-	uint32_t ring_id;
-
-	r = amdgpu_query_hw_ip_info(device_handle, ip_type, 0, &info);
-	CU_ASSERT_EQUAL(r, 0);
-	if (!info.available_rings)
-		printf("SKIP ... as there's no ring for ip %d\n", ip_type);
-
-	for (ring_id = 0; (1 << ring_id) & info.available_rings; ring_id++) {
-		amdgpu_memcpy_dispatch_test(device_handle, ip_type, ring_id, 0);
-		amdgpu_memcpy_dispatch_hang_slow_test(device_handle, ip_type, ring_id);
-		amdgpu_memcpy_dispatch_test(device_handle, ip_type, ring_id, 0);
-	}
-}
-
-static int amdgpu_draw_load_ps_shader_hang_slow(uint32_t *ptr, int family)
-{
-	struct amdgpu_test_shader *shader;
-	int i, loop = 0x40000;
-
-	switch (family) {
-		case AMDGPU_FAMILY_AI:
-		case AMDGPU_FAMILY_RV:
-			shader = &memcpy_ps_hang_slow_ai;
-			break;
-		default:
-			return -1;
-			break;
-	}
-
-	memcpy(ptr, shader->shader, shader->header_length * sizeof(uint32_t));
-
-	for (i = 0; i < loop; i++)
-		memcpy(ptr + shader->header_length + shader->body_length * i,
-			shader->shader + shader->header_length,
-			shader->body_length * sizeof(uint32_t));
-
-	memcpy(ptr + shader->header_length + shader->body_length * loop,
-		shader->shader + shader->header_length + shader->body_length,
-		shader->foot_length * sizeof(uint32_t));
-
-	return 0;
-}
-
-static int amdgpu_draw_load_ps_shader(uint8_t *ptr, int ps_type)
-{
-	int i;
-	uint32_t shader_offset= 256;
-	uint32_t mem_offset, patch_code_offset;
-	uint32_t shader_size, patchinfo_code_size;
-	const uint32_t *shader;
-	const uint32_t *patchinfo_code;
-	const uint32_t *patchcode_offset;
-
-	switch (ps_type) {
-		case PS_CONST:
-			shader = ps_const_shader_gfx9;
-			shader_size = sizeof(ps_const_shader_gfx9);
-			patchinfo_code = (const uint32_t *)ps_const_shader_patchinfo_code_gfx9;
-			patchinfo_code_size = ps_const_shader_patchinfo_code_size_gfx9;
-			patchcode_offset = ps_const_shader_patchinfo_offset_gfx9;
-			break;
-		case PS_TEX:
-			shader = ps_tex_shader_gfx9;
-			shader_size = sizeof(ps_tex_shader_gfx9);
-			patchinfo_code = (const uint32_t *)ps_tex_shader_patchinfo_code_gfx9;
-			patchinfo_code_size = ps_tex_shader_patchinfo_code_size_gfx9;
-			patchcode_offset = ps_tex_shader_patchinfo_offset_gfx9;
-			break;
-		case PS_HANG:
-			shader = memcpy_ps_hang;
-			shader_size = sizeof(memcpy_ps_hang);
-
-			memcpy(ptr, shader, shader_size);
-			return 0;
-		default:
-			return -1;
-			break;
-	}
-
-	/* write main shader program */
-	for (i = 0 ; i < 10; i++) {
-		mem_offset = i * shader_offset;
-		memcpy(ptr + mem_offset, shader, shader_size);
-	}
-
-	/* overwrite patch codes */
-	for (i = 0 ; i < 10; i++) {
-		mem_offset = i * shader_offset + patchcode_offset[0] * sizeof(uint32_t);
-		patch_code_offset = i * patchinfo_code_size;
-		memcpy(ptr + mem_offset,
-			patchinfo_code + patch_code_offset,
-			patchinfo_code_size * sizeof(uint32_t));
-	}
-
-	return 0;
-}
-
-/* load RectPosTexFast_VS */
-static int amdgpu_draw_load_vs_shader(uint8_t *ptr)
-{
-	const uint32_t *shader;
-	uint32_t shader_size;
-
-	shader = vs_RectPosTexFast_shader_gfx9;
-	shader_size = sizeof(vs_RectPosTexFast_shader_gfx9);
-
-	memcpy(ptr, shader, shader_size);
-
-	return 0;
-}
-
-static int amdgpu_draw_init(uint32_t *ptr)
-{
-	int i = 0;
-	const uint32_t *preamblecache_ptr;
-	uint32_t preamblecache_size;
-
-	/* Write context control and load shadowing register if necessary */
-	ptr[i++] = PACKET3(PKT3_CONTEXT_CONTROL, 1);
-	ptr[i++] = 0x80000000;
-	ptr[i++] = 0x80000000;
-
-	preamblecache_ptr = preamblecache_gfx9;
-	preamblecache_size = sizeof(preamblecache_gfx9);
-
-	memcpy(ptr + i, preamblecache_ptr, preamblecache_size);
-	return i + preamblecache_size/sizeof(uint32_t);
-}
-
-static int amdgpu_draw_setup_and_write_drawblt_surf_info(uint32_t *ptr,
-							 uint64_t dst_addr,
-							 int hang_slow)
-{
-	int i = 0;
-
-	/* setup color buffer */
-	/* offset   reg
-	   0xA318   CB_COLOR0_BASE
-	   0xA319   CB_COLOR0_BASE_EXT
-	   0xA31A   CB_COLOR0_ATTRIB2
-	   0xA31B   CB_COLOR0_VIEW
-	   0xA31C   CB_COLOR0_INFO
-	   0xA31D   CB_COLOR0_ATTRIB
-	   0xA31E   CB_COLOR0_DCC_CONTROL
-	   0xA31F   CB_COLOR0_CMASK
-	   0xA320   CB_COLOR0_CMASK_BASE_EXT
-	   0xA321   CB_COLOR0_FMASK
-	   0xA322   CB_COLOR0_FMASK_BASE_EXT
-	   0xA323   CB_COLOR0_CLEAR_WORD0
-	   0xA324   CB_COLOR0_CLEAR_WORD1
-	   0xA325   CB_COLOR0_DCC_BASE
-	   0xA326   CB_COLOR0_DCC_BASE_EXT */
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 15);
-	ptr[i++] = 0x318;
-	ptr[i++] = dst_addr >> 8;
-	ptr[i++] = dst_addr >> 40;
-	ptr[i++] = hang_slow ? 0x1ffc7ff : 0x7c01f;
-	ptr[i++] = 0;
-	ptr[i++] = 0x50438;
-	ptr[i++] = 0x10140000;
-	i += 9;
-
-	/* mmCB_MRT0_EPITCH */
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-	ptr[i++] = 0x1e8;
-	ptr[i++] = hang_slow ? 0x7ff : 0x1f;
-
-	/* 0xA32B   CB_COLOR1_BASE */
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-	ptr[i++] = 0x32b;
-	ptr[i++] = 0;
-
-	/* 0xA33A   CB_COLOR1_BASE */
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-	ptr[i++] = 0x33a;
-	ptr[i++] = 0;
-
-	/* SPI_SHADER_COL_FORMAT */
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-	ptr[i++] = 0x1c5;
-	ptr[i++] = 9;
-
-	/* Setup depth buffer */
-	/* mmDB_Z_INFO */
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 2);
-	ptr[i++] = 0xe;
-	i += 2;
-
-	return i;
-}
-
-static int amdgpu_draw_setup_and_write_drawblt_state(uint32_t *ptr, int hang_slow)
-{
-	int i = 0;
-	const uint32_t *cached_cmd_ptr;
-	uint32_t cached_cmd_size;
-
-	/* mmPA_SC_TILE_STEERING_OVERRIDE */
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-	ptr[i++] = 0xd7;
-	ptr[i++] = 0;
-
-	ptr[i++] = 0xffff1000;
-	ptr[i++] = 0xc0021000;
-
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-	ptr[i++] = 0xd7;
-	ptr[i++] = 1;
-
-	/* mmPA_SC_AA_SAMPLE_LOCS_PIXEL_X0Y0_0 */
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 16);
-	ptr[i++] = 0x2fe;
-	i += 16;
-
-	/* mmPA_SC_CENTROID_PRIORITY_0 */
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 2);
-	ptr[i++] = 0x2f5;
-	i += 2;
-
-	cached_cmd_ptr = cached_cmd_gfx9;
-	cached_cmd_size = sizeof(cached_cmd_gfx9);
-
-	memcpy(ptr + i, cached_cmd_ptr, cached_cmd_size);
-	if (hang_slow)
-		*(ptr + i + 12) = 0x8000800;
-	i += cached_cmd_size/sizeof(uint32_t);
-
-	return i;
-}
-
-static int amdgpu_draw_vs_RectPosTexFast_write2hw(uint32_t *ptr,
-						  int ps_type,
-						  uint64_t shader_addr,
-						  int hang_slow)
-{
-	int i = 0;
-
-	/* mmPA_CL_VS_OUT_CNTL */
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-	ptr[i++] = 0x207;
-	ptr[i++] = 0;
-
-	/* mmSPI_SHADER_PGM_RSRC3_VS */
-	ptr[i++] = PACKET3(PKT3_SET_SH_REG, 1);
-	ptr[i++] = 0x46;
-	ptr[i++] = 0xffff;
-
-	/* mmSPI_SHADER_PGM_LO_VS...mmSPI_SHADER_PGM_HI_VS */
-	ptr[i++] = PACKET3(PKT3_SET_SH_REG, 2);
-	ptr[i++] = 0x48;
-	ptr[i++] = shader_addr >> 8;
-	ptr[i++] = shader_addr >> 40;
-
-	/* mmSPI_SHADER_PGM_RSRC1_VS */
-	ptr[i++] = PACKET3(PKT3_SET_SH_REG, 1);
-	ptr[i++] = 0x4a;
-	ptr[i++] = 0xc0081;
-	/* mmSPI_SHADER_PGM_RSRC2_VS */
-	ptr[i++] = PACKET3(PKT3_SET_SH_REG, 1);
-	ptr[i++] = 0x4b;
-	ptr[i++] = 0x18;
-
-	/* mmSPI_VS_OUT_CONFIG */
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-	ptr[i++] = 0x1b1;
-	ptr[i++] = 2;
-
-	/* mmSPI_SHADER_POS_FORMAT */
-	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-	ptr[i++] = 0x1c3;
-	ptr[i++] = 4;
-
-	ptr[i++] = PACKET3(PKT3_SET_SH_REG, 4);
-	ptr[i++] = 0x4c;
-	i += 2;
-	ptr[i++] = hang_slow ? 0x45000000 : 0x42000000;
-	ptr[i++] = hang_slow ? 0x45000000 : 0x42000000;
-
-	ptr[i++] = PACKET3(PKT3_SET_SH_REG, 4);
-	ptr[i++] = 0x50;
-	i += 2;
-	if (ps_type == PS_CONST) {
-		i += 2;
-	} else if (ps_type == PS_TEX) {
-		ptr[i++] = 0x3f800000;
-		ptr[i++] = 0x3f800000;
-	}
-
-	ptr[i++] = PACKET3(PKT3_SET_SH_REG, 4);
-	ptr[i++] = 0x54;
-	i += 4;
-
-	return i;
-}
-
-static int amdgpu_draw_ps_write2hw(uint32_t *ptr,
-				   int ps_type,
-				   uint64_t shader_addr)
-{
-	int i, j;
-	const uint32_t *sh_registers;
-	const uint32_t *context_registers;
-	uint32_t num_sh_reg, num_context_reg;
-
-	if (ps_type == PS_CONST) {
-		sh_registers = (const uint32_t *)ps_const_sh_registers_gfx9;
-		context_registers = (const uint32_t *)ps_const_context_reg_gfx9;
-		num_sh_reg = ps_num_sh_registers_gfx9;
-		num_context_reg = ps_num_context_registers_gfx9;
-	} else if (ps_type == PS_TEX) {
-		sh_registers = (const uint32_t *)ps_tex_sh_registers_gfx9;
-		context_registers = (const uint32_t *)ps_tex_context_reg_gfx9;
-		num_sh_reg = ps_num_sh_registers_gfx9;
-		num_context_reg = ps_num_context_registers_gfx9;
-	}
-
-	i = 0;
-
-	/* 0x2c07   SPI_SHADER_PGM_RSRC3_PS
-	   0x2c08   SPI_SHADER_PGM_LO_PS
-	   0x2c09   SPI_SHADER_PGM_HI_PS */
-	shader_addr += 256 * 9;
-	ptr[i++] = PACKET3(PKT3_SET_SH_REG, 3);
-	ptr[i++] = 0x7;
-	ptr[i++] = 0xffff;
-	ptr[i++] = shader_addr >> 8;
-	ptr[i++] = shader_addr >> 40;
-
-	for (j = 0; j < num_sh_reg; j++) {
-		ptr[i++] = PACKET3(PKT3_SET_SH_REG, 1);
-		ptr[i++] = sh_registers[j * 2] - 0x2c00;
-		ptr[i++] = sh_registers[j * 2 + 1];
-	}
-
-	for (j = 0; j < num_context_reg; j++) {
-		if (context_registers[j * 2] != 0xA1C5) {
-			ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-			ptr[i++] = context_registers[j * 2] - 0xa000;
-			ptr[i++] = context_registers[j * 2 + 1];
-		}
-
-		if (context_registers[j * 2] == 0xA1B4) {
-			ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-			ptr[i++] = 0x1b3;
-			ptr[i++] = 2;
-		}
-	}
-
-	return i;
-}
-
-static int amdgpu_draw_draw(uint32_t *ptr)
-{
-	int i = 0;
-
-	/* mmIA_MULTI_VGT_PARAM */
-	ptr[i++] = PACKET3(PACKET3_SET_UCONFIG_REG, 1);
-	ptr[i++] = 0x40000258;
-	ptr[i++] = 0xd00ff;
-
-	/* mmVGT_PRIMITIVE_TYPE */
-	ptr[i++] = PACKET3(PACKET3_SET_UCONFIG_REG, 1);
-	ptr[i++] = 0x10000242;
-	ptr[i++] = 0x11;
-
-	ptr[i++] = PACKET3(PACKET3_DRAW_INDEX_AUTO, 1);
-	ptr[i++] = 3;
-	ptr[i++] = 2;
-
-	return i;
-}
-
-void amdgpu_memset_draw(amdgpu_device_handle device_handle,
-			amdgpu_bo_handle bo_shader_ps,
-			amdgpu_bo_handle bo_shader_vs,
-			uint64_t mc_address_shader_ps,
-			uint64_t mc_address_shader_vs,
-			uint32_t ring_id)
-{
-	amdgpu_context_handle context_handle;
-	amdgpu_bo_handle bo_dst, bo_cmd, resources[4];
-	volatile unsigned char *ptr_dst;
-	uint32_t *ptr_cmd;
-	uint64_t mc_address_dst, mc_address_cmd;
-	amdgpu_va_handle va_dst, va_cmd;
-	int i, r;
-	int bo_dst_size = 16384;
-	int bo_cmd_size = 4096;
-	struct amdgpu_cs_request ibs_request = {0};
-	struct amdgpu_cs_ib_info ib_info = {0};
-	struct amdgpu_cs_fence fence_status = {0};
-	uint32_t expired;
-	amdgpu_bo_list_handle bo_list;
-
-	r = amdgpu_cs_ctx_create(device_handle, &context_handle);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_cmd_size, 4096,
-					AMDGPU_GEM_DOMAIN_GTT, 0,
-					&bo_cmd, (void **)&ptr_cmd,
-					&mc_address_cmd, &va_cmd);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_cmd, 0, bo_cmd_size);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_dst_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_dst, (void **)&ptr_dst,
-					&mc_address_dst, &va_dst);
-	CU_ASSERT_EQUAL(r, 0);
-
-	i = 0;
-	i += amdgpu_draw_init(ptr_cmd + i);
-
-	i += amdgpu_draw_setup_and_write_drawblt_surf_info(ptr_cmd + i, mc_address_dst, 0);
-
-	i += amdgpu_draw_setup_and_write_drawblt_state(ptr_cmd + i, 0);
-
-	i += amdgpu_draw_vs_RectPosTexFast_write2hw(ptr_cmd + i, PS_CONST, mc_address_shader_vs, 0);
-
-	i += amdgpu_draw_ps_write2hw(ptr_cmd + i, PS_CONST, mc_address_shader_ps);
-
-	ptr_cmd[i++] = PACKET3(PKT3_SET_SH_REG, 4);
-	ptr_cmd[i++] = 0xc;
-	ptr_cmd[i++] = 0x33333333;
-	ptr_cmd[i++] = 0x33333333;
-	ptr_cmd[i++] = 0x33333333;
-	ptr_cmd[i++] = 0x33333333;
-
-	i += amdgpu_draw_draw(ptr_cmd + i);
-
-	while (i & 7)
-		ptr_cmd[i++] = 0xffff1000; /* type3 nop packet */
-
-	resources[0] = bo_dst;
-	resources[1] = bo_shader_ps;
-	resources[2] = bo_shader_vs;
-	resources[3] = bo_cmd;
-	r = amdgpu_bo_list_create(device_handle, 4, resources, NULL, &bo_list);
-	CU_ASSERT_EQUAL(r, 0);
-
-	ib_info.ib_mc_address = mc_address_cmd;
-	ib_info.size = i;
-	ibs_request.ip_type = AMDGPU_HW_IP_GFX;
-	ibs_request.ring = ring_id;
-	ibs_request.resources = bo_list;
-	ibs_request.number_of_ibs = 1;
-	ibs_request.ibs = &ib_info;
-	ibs_request.fence_info.handle = NULL;
-
-	/* submit CS */
-	r = amdgpu_cs_submit(context_handle, 0, &ibs_request, 1);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_list_destroy(bo_list);
-	CU_ASSERT_EQUAL(r, 0);
-
-	fence_status.ip_type = AMDGPU_HW_IP_GFX;
-	fence_status.ip_instance = 0;
-	fence_status.ring = ring_id;
-	fence_status.context = context_handle;
-	fence_status.fence = ibs_request.seq_no;
-
-	/* wait for IB accomplished */
-	r = amdgpu_cs_query_fence_status(&fence_status,
-					 AMDGPU_TIMEOUT_INFINITE,
-					 0, &expired);
-	CU_ASSERT_EQUAL(r, 0);
-	CU_ASSERT_EQUAL(expired, true);
-
-	/* verify if memset test result meets with expected */
-	i = 0;
-	while(i < bo_dst_size) {
-		CU_ASSERT_EQUAL(ptr_dst[i++], 0x33);
-	}
-
-	r = amdgpu_bo_unmap_and_free(bo_dst, va_dst, mc_address_dst, bo_dst_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_cmd, va_cmd, mc_address_cmd, bo_cmd_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_cs_ctx_free(context_handle);
-	CU_ASSERT_EQUAL(r, 0);
-}
-
-static void amdgpu_memset_draw_test(amdgpu_device_handle device_handle,
-				    uint32_t ring)
-{
-	amdgpu_bo_handle bo_shader_ps, bo_shader_vs;
-	void *ptr_shader_ps;
-	void *ptr_shader_vs;
-	uint64_t mc_address_shader_ps, mc_address_shader_vs;
-	amdgpu_va_handle va_shader_ps, va_shader_vs;
-	int r;
-	int bo_shader_size = 4096;
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_shader_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_shader_ps, &ptr_shader_ps,
-					&mc_address_shader_ps, &va_shader_ps);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_shader_ps, 0, bo_shader_size);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_shader_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_shader_vs, &ptr_shader_vs,
-					&mc_address_shader_vs, &va_shader_vs);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_shader_vs, 0, bo_shader_size);
-
-	r = amdgpu_draw_load_ps_shader(ptr_shader_ps, PS_CONST);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_draw_load_vs_shader(ptr_shader_vs);
-	CU_ASSERT_EQUAL(r, 0);
-
-	amdgpu_memset_draw(device_handle, bo_shader_ps, bo_shader_vs,
-			mc_address_shader_ps, mc_address_shader_vs, ring);
-
-	r = amdgpu_bo_unmap_and_free(bo_shader_ps, va_shader_ps, mc_address_shader_ps, bo_shader_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_shader_vs, va_shader_vs, mc_address_shader_vs, bo_shader_size);
-	CU_ASSERT_EQUAL(r, 0);
-}
-
-static void amdgpu_memcpy_draw(amdgpu_device_handle device_handle,
-			       amdgpu_bo_handle bo_shader_ps,
-			       amdgpu_bo_handle bo_shader_vs,
-			       uint64_t mc_address_shader_ps,
-			       uint64_t mc_address_shader_vs,
-			       uint32_t ring, int hang)
-{
-	amdgpu_context_handle context_handle;
-	amdgpu_bo_handle bo_dst, bo_src, bo_cmd, resources[5];
-	volatile unsigned char *ptr_dst;
-	unsigned char *ptr_src;
-	uint32_t *ptr_cmd;
-	uint64_t mc_address_dst, mc_address_src, mc_address_cmd;
-	amdgpu_va_handle va_dst, va_src, va_cmd;
-	int i, r;
-	int bo_size = 16384;
-	int bo_cmd_size = 4096;
-	struct amdgpu_cs_request ibs_request = {0};
-	struct amdgpu_cs_ib_info ib_info= {0};
-	uint32_t hang_state, hangs;
-	uint32_t expired;
-	amdgpu_bo_list_handle bo_list;
-	struct amdgpu_cs_fence fence_status = {0};
-
-	r = amdgpu_cs_ctx_create(device_handle, &context_handle);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_cmd_size, 4096,
-				    AMDGPU_GEM_DOMAIN_GTT, 0,
-				    &bo_cmd, (void **)&ptr_cmd,
-				    &mc_address_cmd, &va_cmd);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_cmd, 0, bo_cmd_size);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_src, (void **)&ptr_src,
-					&mc_address_src, &va_src);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_dst, (void **)&ptr_dst,
-					&mc_address_dst, &va_dst);
-	CU_ASSERT_EQUAL(r, 0);
-
-	memset(ptr_src, 0x55, bo_size);
-
-	i = 0;
-	i += amdgpu_draw_init(ptr_cmd + i);
-
-	i += amdgpu_draw_setup_and_write_drawblt_surf_info(ptr_cmd + i, mc_address_dst, 0);
-
-	i += amdgpu_draw_setup_and_write_drawblt_state(ptr_cmd + i, 0);
-
-	i += amdgpu_draw_vs_RectPosTexFast_write2hw(ptr_cmd + i, PS_TEX, mc_address_shader_vs, 0);
-
-	i += amdgpu_draw_ps_write2hw(ptr_cmd + i, PS_TEX, mc_address_shader_ps);
-
-	ptr_cmd[i++] = PACKET3(PKT3_SET_SH_REG, 8);
-	ptr_cmd[i++] = 0xc;
-	ptr_cmd[i++] = mc_address_src >> 8;
-	ptr_cmd[i++] = mc_address_src >> 40 | 0x10e00000;
-	ptr_cmd[i++] = 0x7c01f;
-	ptr_cmd[i++] = 0x90500fac;
-	ptr_cmd[i++] = 0x3e000;
-	i += 3;
-
-	ptr_cmd[i++] = PACKET3(PKT3_SET_SH_REG, 4);
-	ptr_cmd[i++] = 0x14;
-	ptr_cmd[i++] = 0x92;
-	i += 3;
-
-	ptr_cmd[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-	ptr_cmd[i++] = 0x191;
-	ptr_cmd[i++] = 0;
-
-	i += amdgpu_draw_draw(ptr_cmd + i);
-
-	while (i & 7)
-		ptr_cmd[i++] = 0xffff1000; /* type3 nop packet */
-
-	resources[0] = bo_dst;
-	resources[1] = bo_src;
-	resources[2] = bo_shader_ps;
-	resources[3] = bo_shader_vs;
-	resources[4] = bo_cmd;
-	r = amdgpu_bo_list_create(device_handle, 5, resources, NULL, &bo_list);
-	CU_ASSERT_EQUAL(r, 0);
-
-	ib_info.ib_mc_address = mc_address_cmd;
-	ib_info.size = i;
-	ibs_request.ip_type = AMDGPU_HW_IP_GFX;
-	ibs_request.ring = ring;
-	ibs_request.resources = bo_list;
-	ibs_request.number_of_ibs = 1;
-	ibs_request.ibs = &ib_info;
-	ibs_request.fence_info.handle = NULL;
-	r = amdgpu_cs_submit(context_handle, 0, &ibs_request, 1);
-	CU_ASSERT_EQUAL(r, 0);
-
-	fence_status.ip_type = AMDGPU_HW_IP_GFX;
-	fence_status.ip_instance = 0;
-	fence_status.ring = ring;
-	fence_status.context = context_handle;
-	fence_status.fence = ibs_request.seq_no;
-
-	/* wait for IB accomplished */
-	r = amdgpu_cs_query_fence_status(&fence_status,
-					 AMDGPU_TIMEOUT_INFINITE,
-					 0, &expired);
-	if (!hang) {
-		CU_ASSERT_EQUAL(r, 0);
-		CU_ASSERT_EQUAL(expired, true);
-
-		/* verify if memcpy test result meets with expected */
-		i = 0;
-		while(i < bo_size) {
-			CU_ASSERT_EQUAL(ptr_dst[i], ptr_src[i]);
-			i++;
-		}
-	} else {
-		r = amdgpu_cs_query_reset_state(context_handle, &hang_state, &hangs);
-		CU_ASSERT_EQUAL(r, 0);
-		CU_ASSERT_EQUAL(hang_state, AMDGPU_CTX_UNKNOWN_RESET);
-	}
-
-	r = amdgpu_bo_list_destroy(bo_list);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_src, va_src, mc_address_src, bo_size);
-	CU_ASSERT_EQUAL(r, 0);
-	r = amdgpu_bo_unmap_and_free(bo_dst, va_dst, mc_address_dst, bo_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_cmd, va_cmd, mc_address_cmd, bo_cmd_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_cs_ctx_free(context_handle);
-	CU_ASSERT_EQUAL(r, 0);
-}
-
-void amdgpu_memcpy_draw_test(amdgpu_device_handle device_handle, uint32_t ring,
-			     int hang)
-{
-	amdgpu_bo_handle bo_shader_ps, bo_shader_vs;
-	void *ptr_shader_ps;
-	void *ptr_shader_vs;
-	uint64_t mc_address_shader_ps, mc_address_shader_vs;
-	amdgpu_va_handle va_shader_ps, va_shader_vs;
-	int bo_shader_size = 4096;
-	enum ps_type ps_type = hang ? PS_HANG : PS_TEX;
-	int r;
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_shader_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_shader_ps, &ptr_shader_ps,
-					&mc_address_shader_ps, &va_shader_ps);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_shader_ps, 0, bo_shader_size);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_shader_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_shader_vs, &ptr_shader_vs,
-					&mc_address_shader_vs, &va_shader_vs);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_shader_vs, 0, bo_shader_size);
-
-	r = amdgpu_draw_load_ps_shader(ptr_shader_ps, ps_type);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_draw_load_vs_shader(ptr_shader_vs);
-	CU_ASSERT_EQUAL(r, 0);
-
-	amdgpu_memcpy_draw(device_handle, bo_shader_ps, bo_shader_vs,
-			mc_address_shader_ps, mc_address_shader_vs, ring, hang);
-
-	r = amdgpu_bo_unmap_and_free(bo_shader_ps, va_shader_ps, mc_address_shader_ps, bo_shader_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_shader_vs, va_shader_vs, mc_address_shader_vs, bo_shader_size);
-	CU_ASSERT_EQUAL(r, 0);
-}
-
-static void amdgpu_draw_test(void)
-{
-	int r;
-	struct drm_amdgpu_info_hw_ip info;
-	uint32_t ring_id;
-
-	r = amdgpu_query_hw_ip_info(device_handle, AMDGPU_HW_IP_GFX, 0, &info);
-	CU_ASSERT_EQUAL(r, 0);
-	if (!info.available_rings)
-		printf("SKIP ... as there's no graphics ring\n");
-
-	for (ring_id = 0; (1 << ring_id) & info.available_rings; ring_id++) {
-		amdgpu_memset_draw_test(device_handle, ring_id);
-		amdgpu_memcpy_draw_test(device_handle, ring_id, 0);
-	}
-}
-
-void amdgpu_memcpy_draw_hang_slow_test(amdgpu_device_handle device_handle, uint32_t ring)
-{
-	amdgpu_context_handle context_handle;
-	amdgpu_bo_handle bo_shader_ps, bo_shader_vs;
-	amdgpu_bo_handle bo_dst, bo_src, bo_cmd, resources[5];
-	void *ptr_shader_ps;
-	void *ptr_shader_vs;
-	volatile unsigned char *ptr_dst;
-	unsigned char *ptr_src;
-	uint32_t *ptr_cmd;
-	uint64_t mc_address_dst, mc_address_src, mc_address_cmd;
-	uint64_t mc_address_shader_ps, mc_address_shader_vs;
-	amdgpu_va_handle va_shader_ps, va_shader_vs;
-	amdgpu_va_handle va_dst, va_src, va_cmd;
-	struct amdgpu_gpu_info gpu_info = {0};
-	int i, r;
-	int bo_size = 0x4000000;
-	int bo_shader_ps_size = 0x400000;
-	int bo_shader_vs_size = 4096;
-	int bo_cmd_size = 4096;
-	struct amdgpu_cs_request ibs_request = {0};
-	struct amdgpu_cs_ib_info ib_info= {0};
-	uint32_t hang_state, hangs, expired;
-	amdgpu_bo_list_handle bo_list;
-	struct amdgpu_cs_fence fence_status = {0};
-
-	r = amdgpu_query_gpu_info(device_handle, &gpu_info);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_cs_ctx_create(device_handle, &context_handle);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_cmd_size, 4096,
-				    AMDGPU_GEM_DOMAIN_GTT, 0,
-				    &bo_cmd, (void **)&ptr_cmd,
-				    &mc_address_cmd, &va_cmd);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_cmd, 0, bo_cmd_size);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_shader_ps_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_shader_ps, &ptr_shader_ps,
-					&mc_address_shader_ps, &va_shader_ps);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_shader_ps, 0, bo_shader_ps_size);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_shader_vs_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_shader_vs, &ptr_shader_vs,
-					&mc_address_shader_vs, &va_shader_vs);
-	CU_ASSERT_EQUAL(r, 0);
-	memset(ptr_shader_vs, 0, bo_shader_vs_size);
-
-	r = amdgpu_draw_load_ps_shader_hang_slow(ptr_shader_ps, gpu_info.family_id);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_draw_load_vs_shader(ptr_shader_vs);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_src, (void **)&ptr_src,
-					&mc_address_src, &va_src);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_alloc_and_map(device_handle, bo_size, 4096,
-					AMDGPU_GEM_DOMAIN_VRAM, 0,
-					&bo_dst, (void **)&ptr_dst,
-					&mc_address_dst, &va_dst);
-	CU_ASSERT_EQUAL(r, 0);
-
-	memset(ptr_src, 0x55, bo_size);
-
-	i = 0;
-	i += amdgpu_draw_init(ptr_cmd + i);
-
-	i += amdgpu_draw_setup_and_write_drawblt_surf_info(ptr_cmd + i, mc_address_dst, 1);
-
-	i += amdgpu_draw_setup_and_write_drawblt_state(ptr_cmd + i, 1);
-
-	i += amdgpu_draw_vs_RectPosTexFast_write2hw(ptr_cmd + i, PS_TEX,
-							mc_address_shader_vs, 1);
-
-	i += amdgpu_draw_ps_write2hw(ptr_cmd + i, PS_TEX, mc_address_shader_ps);
-
-	ptr_cmd[i++] = PACKET3(PKT3_SET_SH_REG, 8);
-	ptr_cmd[i++] = 0xc;
-	ptr_cmd[i++] = mc_address_src >> 8;
-	ptr_cmd[i++] = mc_address_src >> 40 | 0x10e00000;
-	ptr_cmd[i++] = 0x1ffc7ff;
-	ptr_cmd[i++] = 0x90500fac;
-	ptr_cmd[i++] = 0xffe000;
-	i += 3;
-
-	ptr_cmd[i++] = PACKET3(PKT3_SET_SH_REG, 4);
-	ptr_cmd[i++] = 0x14;
-	ptr_cmd[i++] = 0x92;
-	i += 3;
-
-	ptr_cmd[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
-	ptr_cmd[i++] = 0x191;
-	ptr_cmd[i++] = 0;
-
-	i += amdgpu_draw_draw(ptr_cmd + i);
-
-	while (i & 7)
-		ptr_cmd[i++] = 0xffff1000; /* type3 nop packet */
-
-	resources[0] = bo_dst;
-	resources[1] = bo_src;
-	resources[2] = bo_shader_ps;
-	resources[3] = bo_shader_vs;
-	resources[4] = bo_cmd;
-	r = amdgpu_bo_list_create(device_handle, 5, resources, NULL, &bo_list);
-	CU_ASSERT_EQUAL(r, 0);
-
-	ib_info.ib_mc_address = mc_address_cmd;
-	ib_info.size = i;
-	ibs_request.ip_type = AMDGPU_HW_IP_GFX;
-	ibs_request.ring = ring;
-	ibs_request.resources = bo_list;
-	ibs_request.number_of_ibs = 1;
-	ibs_request.ibs = &ib_info;
-	ibs_request.fence_info.handle = NULL;
-	r = amdgpu_cs_submit(context_handle, 0, &ibs_request, 1);
-	CU_ASSERT_EQUAL(r, 0);
-
-	fence_status.ip_type = AMDGPU_HW_IP_GFX;
-	fence_status.ip_instance = 0;
-	fence_status.ring = ring;
-	fence_status.context = context_handle;
-	fence_status.fence = ibs_request.seq_no;
-
-	/* wait for IB accomplished */
-	r = amdgpu_cs_query_fence_status(&fence_status,
-					 AMDGPU_TIMEOUT_INFINITE,
-					 0, &expired);
-
-	r = amdgpu_cs_query_reset_state(context_handle, &hang_state, &hangs);
-	CU_ASSERT_EQUAL(r, 0);
-	CU_ASSERT_EQUAL(hang_state, AMDGPU_CTX_UNKNOWN_RESET);
-
-	r = amdgpu_bo_list_destroy(bo_list);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_dst, va_dst, mc_address_dst, bo_size);
-	CU_ASSERT_EQUAL(r, 0);
-	r = amdgpu_bo_unmap_and_free(bo_src, va_src, mc_address_src, bo_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_cmd, va_cmd, mc_address_cmd, bo_cmd_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_bo_unmap_and_free(bo_shader_ps, va_shader_ps, mc_address_shader_ps, bo_shader_ps_size);
-	CU_ASSERT_EQUAL(r, 0);
-	r = amdgpu_bo_unmap_and_free(bo_shader_vs, va_shader_vs, mc_address_shader_vs, bo_shader_vs_size);
-	CU_ASSERT_EQUAL(r, 0);
-
-	r = amdgpu_cs_ctx_free(context_handle);
-	CU_ASSERT_EQUAL(r, 0);
-}
-
 static void amdgpu_gpu_reset_test(void)
 {
 	int r;
diff --git a/tests/amdgpu/cp_dma_tests.c b/tests/amdgpu/cp_dma_tests.c
new file mode 100644
index 00000000..e82214fe
--- /dev/null
+++ b/tests/amdgpu/cp_dma_tests.c
@@ -0,0 +1,533 @@
+/*
+ * Copyright 2022 Advanced Micro Devices, Inc.
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ *
+*/
+
+#include <unistd.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <inttypes.h>
+
+#include "CUnit/Basic.h"
+
+#include "amdgpu_test.h"
+#include "amdgpu_drm.h"
+#include "amdgpu_internal.h"
+
+#define IB_SIZE 4096
+#define MAX_RESOURCES 8
+
+#define DMA_SIZE 4097 
+#define DMA_DATA_BYTE 0xea
+
+static bool do_p2p;
+
+static amdgpu_device_handle executing_device_handle;
+static uint32_t executing_device_major_version;
+static uint32_t executing_device_minor_version;
+
+static amdgpu_device_handle peer_exporting_device_handle;
+static uint32_t peer_exporting_device_major_version;
+static uint32_t peer_exporting_device_minor_version;
+
+static amdgpu_context_handle context_handle;
+static amdgpu_bo_handle ib_handle;
+static uint32_t *ib_cpu;
+static uint64_t ib_mc_address;
+static amdgpu_va_handle ib_va_handle;
+static uint32_t num_dword;
+
+static amdgpu_bo_handle resources[MAX_RESOURCES];
+static unsigned num_resources;
+
+static uint8_t* reference_data;
+
+static void amdgpu_cp_dma_host_to_vram(void);
+static void amdgpu_cp_dma_vram_to_host(void);
+static void amdgpu_cp_dma_p2p_vram_to_vram(void);
+static void amdgpu_cp_dma_p2p_host_to_vram(void);
+static void amdgpu_cp_dma_p2p_vram_to_host(void);
+
+/**
+ * Tests in cp dma test suite
+ */
+CU_TestInfo cp_dma_tests[] = {
+	{ "CP DMA write Host to VRAM",  amdgpu_cp_dma_host_to_vram },
+	{ "CP DMA write VRAM to Host",  amdgpu_cp_dma_vram_to_host },
+
+	{ "Peer to Peer CP DMA write VRAM to VRAM",  amdgpu_cp_dma_p2p_vram_to_vram },
+	{ "Peer to Peer CP DMA write Host to VRAM",  amdgpu_cp_dma_p2p_host_to_vram },
+	{ "Peer to Peer CP DMA write VRAM to Host",  amdgpu_cp_dma_p2p_vram_to_host },
+	CU_TEST_INFO_NULL,
+};
+
+struct amdgpu_cp_dma_bo{
+	amdgpu_bo_handle buf_handle;
+	amdgpu_va_handle va_handle;
+	uint64_t gpu_va;
+	uint64_t size;
+};
+
+static int allocate_bo_and_va(amdgpu_device_handle dev,
+		uint64_t size, uint64_t alignment,
+		uint32_t heap, uint64_t alloc_flags,
+		struct amdgpu_cp_dma_bo *bo) {
+	struct amdgpu_bo_alloc_request request = {};
+	amdgpu_bo_handle buf_handle;
+	amdgpu_va_handle va_handle;
+	uint64_t vmc_addr;
+	int r;
+
+	request.alloc_size = size;
+	request.phys_alignment = alignment;
+	request.preferred_heap = heap;
+	request.flags = alloc_flags;
+
+	r = amdgpu_bo_alloc(dev, &request, &buf_handle);
+	if (r)
+		goto error_bo_alloc;
+
+	r = amdgpu_va_range_alloc(dev, amdgpu_gpu_va_range_general,
+			size, alignment, 0,
+			&vmc_addr, &va_handle, 0);
+	if (r)
+		goto error_va_alloc;
+
+	r = amdgpu_bo_va_op(buf_handle, 0, size, vmc_addr,
+						AMDGPU_VM_PAGE_READABLE |
+							AMDGPU_VM_PAGE_WRITEABLE |
+							AMDGPU_VM_PAGE_EXECUTABLE,
+						AMDGPU_VA_OP_MAP);
+	if (r)
+		goto error_va_map;
+
+	bo->buf_handle = buf_handle;
+	bo->va_handle = va_handle;
+	bo->gpu_va = vmc_addr;
+	bo->size = size;
+
+	return 0;
+
+error_va_map:
+	amdgpu_bo_va_op(buf_handle, 0,
+			size, vmc_addr, 0, AMDGPU_VA_OP_UNMAP);
+
+error_va_alloc:
+	amdgpu_va_range_free(va_handle);
+
+error_bo_alloc:
+	amdgpu_bo_free(buf_handle);
+
+	return r;
+}
+
+static int import_dma_buf_to_bo(amdgpu_device_handle dev,
+		int dmabuf_fd, struct amdgpu_cp_dma_bo *bo) {
+	amdgpu_va_handle va_handle;
+	uint64_t vmc_addr;
+	int r;
+	struct amdgpu_bo_import_result bo_import_result = {};
+
+	r = amdgpu_bo_import(dev, amdgpu_bo_handle_type_dma_buf_fd,
+			dmabuf_fd, &bo_import_result);
+	if (r)
+		goto error_bo_import;
+
+	r = amdgpu_va_range_alloc(dev, amdgpu_gpu_va_range_general,
+				bo_import_result.alloc_size, 0, 0,
+				&vmc_addr, &va_handle, 0);
+	if (r)
+		goto error_va_alloc;
+
+	r = amdgpu_bo_va_op(bo_import_result.buf_handle, 0,
+			bo_import_result.alloc_size, vmc_addr,
+			AMDGPU_VM_PAGE_READABLE |
+				AMDGPU_VM_PAGE_WRITEABLE |
+				AMDGPU_VM_PAGE_EXECUTABLE,
+			AMDGPU_VA_OP_MAP);
+	if (r)
+		goto error_va_map;
+
+	bo->buf_handle = bo_import_result.buf_handle;
+	bo->va_handle = va_handle;
+	bo->gpu_va = vmc_addr;
+	bo->size = bo_import_result.alloc_size;
+
+	return 0;
+
+error_va_map:
+	amdgpu_bo_va_op(bo_import_result.buf_handle, 0,
+			bo_import_result.alloc_size, vmc_addr, 0, AMDGPU_VA_OP_UNMAP);
+
+error_va_alloc:
+	amdgpu_va_range_free(va_handle);
+
+error_bo_import:
+	amdgpu_bo_free(bo_import_result.buf_handle);
+
+	return r;
+}
+
+static int free_bo(struct amdgpu_cp_dma_bo bo) {
+	int r;
+	r = amdgpu_bo_va_op(bo.buf_handle, 0,
+			bo.size, bo.gpu_va, 0, AMDGPU_VA_OP_UNMAP);
+	if(r)
+		return r;
+
+	r = amdgpu_va_range_free(bo.va_handle);
+	if(r)
+		return r;
+
+	r = amdgpu_bo_free(bo.buf_handle);
+	if(r)
+		return r;
+
+	return 0;
+}
+
+static int submit_and_sync() {
+	struct amdgpu_cs_request ibs_request = {0};
+	struct amdgpu_cs_ib_info ib_info = {0};
+	struct amdgpu_cs_fence fence_status = {0};
+	uint32_t expired;
+	uint32_t family_id, chip_id, chip_rev;
+	unsigned gc_ip_type;
+	int r;
+
+	r = amdgpu_bo_list_create(executing_device_handle,
+			num_resources, resources,
+			NULL, &ibs_request.resources);
+	if (r)
+		return r;
+
+	family_id = executing_device_handle->info.family_id;
+	chip_id = executing_device_handle->info.chip_external_rev;
+	chip_rev = executing_device_handle->info.chip_rev;
+
+	gc_ip_type = (asic_is_gfx_pipe_removed(family_id, chip_id, chip_rev)) ?
+		AMDGPU_HW_IP_COMPUTE : AMDGPU_HW_IP_GFX;
+
+	ib_info.ib_mc_address = ib_mc_address;
+	ib_info.size = num_dword;
+
+	ibs_request.ip_type = gc_ip_type;
+	ibs_request.number_of_ibs = 1;
+	ibs_request.ibs = &ib_info;
+	ibs_request.fence_info.handle = NULL;
+
+	r = amdgpu_cs_submit(context_handle, 0, &ibs_request, 1);
+	if (r)
+		return r;
+
+	r = amdgpu_bo_list_destroy(ibs_request.resources);
+	if (r)
+		return r;
+
+	fence_status.context = context_handle;
+	fence_status.ip_type = gc_ip_type;
+	fence_status.fence = ibs_request.seq_no;
+
+	r = amdgpu_cs_query_fence_status(&fence_status,
+			AMDGPU_TIMEOUT_INFINITE,
+			0, &expired);
+	if (r)
+		return r;
+
+	return 0;
+} 
+
+static void cp_dma_cmd(struct amdgpu_cp_dma_bo src_bo,
+		struct amdgpu_cp_dma_bo dst_bo) {
+	_Static_assert(DMA_SIZE < (1 << 26), "DMA size exceeds CP DMA maximium!");
+
+	ib_cpu[0] = 0xc0055000;
+	ib_cpu[1] = 0x80000000;
+	ib_cpu[2] = src_bo.gpu_va & 0x00000000ffffffff;
+	ib_cpu[3] = (src_bo.gpu_va & 0xffffffff00000000) >> 32;
+	ib_cpu[4] = dst_bo.gpu_va & 0x00000000ffffffff;
+	ib_cpu[5] = (dst_bo.gpu_va & 0xffffffff00000000) >> 32;
+	// size is read from the lower 26bits. 
+	ib_cpu[6] = ((1 << 26) - 1) & DMA_SIZE;
+	ib_cpu[7] = 0xffff1000;
+
+	num_dword = 8;
+
+	resources[0] = src_bo.buf_handle;
+	resources[1] = dst_bo.buf_handle;
+	resources[2] = ib_handle;
+	num_resources = 3;
+}
+
+static void amdgpu_cp_dma(uint32_t src_heap, uint32_t dst_heap) {
+	int r;
+	struct amdgpu_cp_dma_bo src_bo = {0};
+	struct amdgpu_cp_dma_bo dst_bo = {0};
+	void *src_bo_cpu;
+	void *dst_bo_cpu;
+
+	/* allocate the src bo, set its data to DMA_DATA_BYTE */
+	r = allocate_bo_and_va(executing_device_handle, DMA_SIZE, 4096,
+			src_heap, AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED, &src_bo);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = amdgpu_bo_cpu_map(src_bo.buf_handle, (void **)&src_bo_cpu);
+	CU_ASSERT_EQUAL(r, 0);
+	memset(src_bo_cpu, DMA_DATA_BYTE, DMA_SIZE);
+
+	r = amdgpu_bo_cpu_unmap(src_bo.buf_handle);
+	CU_ASSERT_EQUAL(r, 0);
+
+	/* allocate the dst bo and clear its content to all 0 */
+	r = allocate_bo_and_va(executing_device_handle, DMA_SIZE, 4096,
+			dst_heap, AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED, &dst_bo);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = amdgpu_bo_cpu_map(dst_bo.buf_handle, (void **)&dst_bo_cpu);
+	CU_ASSERT_EQUAL(r, 0);
+
+	_Static_assert(DMA_DATA_BYTE != 0, "Initialization data should be different from DMA data!");
+	memset(dst_bo_cpu, 0, DMA_SIZE);
+
+	/* record CP DMA command and dispatch the command */
+	cp_dma_cmd(src_bo, dst_bo);
+
+	r = submit_and_sync();
+	CU_ASSERT_EQUAL(r, 0);
+
+	/* verify the dst bo is filled with DMA_DATA_BYTE */
+	CU_ASSERT_EQUAL(memcmp(dst_bo_cpu, reference_data, DMA_SIZE) == 0, true);
+
+	r = amdgpu_bo_cpu_unmap(dst_bo.buf_handle);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = free_bo(src_bo);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = free_bo(dst_bo);
+	CU_ASSERT_EQUAL(r, 0);
+}
+
+static void amdgpu_cp_dma_p2p(uint32_t src_heap, uint32_t dst_heap) {
+	int r;
+	struct amdgpu_cp_dma_bo exported_bo = {0};
+	int dma_buf_fd;
+	int dma_buf_fd_dup;
+	struct amdgpu_cp_dma_bo src_bo = {0};
+	struct amdgpu_cp_dma_bo imported_dst_bo = {0};
+	void *exported_bo_cpu;
+	void *src_bo_cpu;
+
+	/* allocate a bo on the peer device and export it to dma-buf */
+	r = allocate_bo_and_va(peer_exporting_device_handle, DMA_SIZE, 4096,
+			src_heap, AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED, &exported_bo);
+	CU_ASSERT_EQUAL(r, 0);
+
+	/* map the exported bo and clear its content to 0 */
+	_Static_assert(DMA_DATA_BYTE != 0, "Initialization data should be different from DMA data!");
+	r = amdgpu_bo_cpu_map(exported_bo.buf_handle, (void **)&exported_bo_cpu);
+	CU_ASSERT_EQUAL(r, 0);
+	memset(exported_bo_cpu, 0, DMA_SIZE);
+
+	r = amdgpu_bo_export(exported_bo.buf_handle,
+			amdgpu_bo_handle_type_dma_buf_fd, (uint32_t*)&dma_buf_fd);
+	CU_ASSERT_EQUAL(r, 0);
+
+    // According to amdgpu_drm:
+	// "Buffer must be "imported" only using new "fd"
+	// (different from one used by "exporter")"
+	dma_buf_fd_dup = dup(dma_buf_fd);
+	r = close(dma_buf_fd);
+	CU_ASSERT_EQUAL(r, 0);
+
+	/* import the dma-buf to the executing device, imported bo is the DMA destination */
+	r = import_dma_buf_to_bo(
+			executing_device_handle, dma_buf_fd_dup, &imported_dst_bo);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = close(dma_buf_fd_dup);
+	CU_ASSERT_EQUAL(r, 0);
+
+	/* allocate the src bo and set its content to DMA_DATA_BYTE */
+	r = allocate_bo_and_va(executing_device_handle, DMA_SIZE, 4096,
+			dst_heap, AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED, &src_bo);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = amdgpu_bo_cpu_map(src_bo.buf_handle, (void **)&src_bo_cpu);
+	CU_ASSERT_EQUAL(r, 0);
+
+	memset(src_bo_cpu, DMA_DATA_BYTE, DMA_SIZE);
+
+	r = amdgpu_bo_cpu_unmap(src_bo.buf_handle);
+	CU_ASSERT_EQUAL(r, 0);
+
+	/* record CP DMA command and dispatch the command */
+	cp_dma_cmd(src_bo, imported_dst_bo);
+
+	r = submit_and_sync();
+	CU_ASSERT_EQUAL(r, 0);
+
+	/* verify the bo from the peer device is filled with DMA_DATA_BYTE */
+	CU_ASSERT_EQUAL(memcmp(exported_bo_cpu, reference_data, DMA_SIZE) == 0, true);
+
+	r = amdgpu_bo_cpu_unmap(exported_bo.buf_handle);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = free_bo(exported_bo);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = free_bo(imported_dst_bo);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = free_bo(src_bo);
+	CU_ASSERT_EQUAL(r, 0);
+}
+
+static void amdgpu_cp_dma_host_to_vram(void) {
+	amdgpu_cp_dma(AMDGPU_GEM_DOMAIN_GTT, AMDGPU_GEM_DOMAIN_VRAM);
+}
+
+static void amdgpu_cp_dma_vram_to_host(void) {
+	amdgpu_cp_dma(AMDGPU_GEM_DOMAIN_VRAM, AMDGPU_GEM_DOMAIN_GTT);
+}
+
+static void amdgpu_cp_dma_p2p_vram_to_vram(void) {
+	amdgpu_cp_dma_p2p(AMDGPU_GEM_DOMAIN_VRAM, AMDGPU_GEM_DOMAIN_VRAM);
+}
+
+static void amdgpu_cp_dma_p2p_host_to_vram(void) {
+	amdgpu_cp_dma_p2p(AMDGPU_GEM_DOMAIN_GTT, AMDGPU_GEM_DOMAIN_VRAM);
+}
+
+static void amdgpu_cp_dma_p2p_vram_to_host(void) {
+	amdgpu_cp_dma_p2p(AMDGPU_GEM_DOMAIN_VRAM, AMDGPU_GEM_DOMAIN_GTT);
+}
+
+int suite_cp_dma_tests_init() {
+	int r;
+	
+	r = amdgpu_device_initialize(drm_amdgpu[0],
+			&executing_device_major_version,
+			&executing_device_minor_version,
+			&executing_device_handle);
+	if (r)
+		return CUE_SINIT_FAILED;
+	
+	r = amdgpu_cs_ctx_create(executing_device_handle, &context_handle);
+	if (r)
+		return CUE_SINIT_FAILED;
+
+	r = amdgpu_bo_alloc_and_map(executing_device_handle, IB_SIZE, 4096,
+					AMDGPU_GEM_DOMAIN_GTT, 0,
+					&ib_handle, (void**)&ib_cpu,
+					&ib_mc_address, &ib_va_handle);
+	if (r)
+		return CUE_SINIT_FAILED;
+	
+	if (do_p2p) {
+		r = amdgpu_device_initialize(drm_amdgpu[1],
+				&peer_exporting_device_major_version,
+				&peer_exporting_device_minor_version,
+				&peer_exporting_device_handle);
+		
+		if (r)
+			return CUE_SINIT_FAILED;
+	}
+
+	reference_data = (uint8_t*)malloc(DMA_SIZE);
+	if (!reference_data)
+		return CUE_SINIT_FAILED;
+	memset(reference_data, DMA_DATA_BYTE, DMA_SIZE);
+
+	return CUE_SUCCESS;
+}
+
+int suite_cp_dma_tests_clean() {
+	int r;
+
+	free(reference_data);
+
+	r = amdgpu_bo_unmap_and_free(ib_handle, ib_va_handle,
+				 ib_mc_address, IB_SIZE);
+	if (r)
+		return CUE_SCLEAN_FAILED;
+
+	r = amdgpu_cs_ctx_free(context_handle);
+	if (r)
+		return CUE_SCLEAN_FAILED;
+
+	r = amdgpu_device_deinitialize(executing_device_handle);
+	if (r)
+		return CUE_SCLEAN_FAILED;
+
+	if (do_p2p) {
+		r = amdgpu_device_deinitialize(peer_exporting_device_handle);
+		if (r)
+			return CUE_SCLEAN_FAILED;
+	}
+
+	return CUE_SUCCESS;
+}
+
+CU_BOOL suite_cp_dma_tests_enable(void) {
+	int r = 0;
+
+	if (amdgpu_device_initialize(drm_amdgpu[0],
+			&executing_device_major_version,
+			&executing_device_minor_version,
+			&executing_device_handle))
+		return CU_FALSE;
+
+	if (!(executing_device_handle->info.family_id >= AMDGPU_FAMILY_AI &&
+			executing_device_handle->info.family_id <= AMDGPU_FAMILY_NV)) {
+		printf("Testing device has ASIC that is not supported by CP-DMA test suite!\n");
+		return CU_FALSE;
+	}
+
+	if (amdgpu_device_deinitialize(executing_device_handle))
+		return CU_FALSE;	
+
+	if (drm_amdgpu[1] >= 0) {
+		r = amdgpu_device_initialize(drm_amdgpu[1],
+				&peer_exporting_device_major_version,
+				&peer_exporting_device_minor_version,
+				&peer_exporting_device_handle);
+		
+		if (r == 0 && (peer_exporting_device_handle->info.family_id >= AMDGPU_FAMILY_AI &&
+						peer_exporting_device_handle->info.family_id <= AMDGPU_FAMILY_NV)) {
+			do_p2p = true;
+		}
+
+		if (r == 0 && amdgpu_device_deinitialize(peer_exporting_device_handle) != 0) {
+			printf("Deinitialize peer_exporting_device_handle failed!\n");
+			return CU_FALSE;
+		}
+	}
+
+	if (!do_p2p) {
+		amdgpu_set_test_active("CP DMA Tests", "Peer to Peer CP DMA write VRAM to VRAM", CU_FALSE);
+		amdgpu_set_test_active("CP DMA Tests", "Peer to Peer CP DMA write Host to VRAM", CU_FALSE);
+		amdgpu_set_test_active("CP DMA Tests", "Peer to Peer CP DMA write VRAM to Host", CU_FALSE);
+		printf("Peer device is not opened or has ASIC not supported by the suite, skip all Peer to Peer tests.\n");
+	}
+	
+	return CU_TRUE;
+}
diff --git a/tests/amdgpu/deadlock_tests.c b/tests/amdgpu/deadlock_tests.c
index 07a39446..2928233d 100644
--- a/tests/amdgpu/deadlock_tests.c
+++ b/tests/amdgpu/deadlock_tests.c
@@ -124,6 +124,8 @@ static void amdgpu_dispatch_hang_slow_gfx(void);
 static void amdgpu_dispatch_hang_slow_compute(void);
 static void amdgpu_draw_hang_gfx(void);
 static void amdgpu_draw_hang_slow_gfx(void);
+static void amdgpu_hang_sdma(void);
+static void amdgpu_hang_slow_sdma(void);
 
 CU_BOOL suite_deadlock_tests_enable(void)
 {
@@ -139,11 +141,13 @@ CU_BOOL suite_deadlock_tests_enable(void)
 
 	/*
 	 * Only enable for ASICs supporting GPU reset and for which it's enabled
-	 * by default (currently GFX8/9 dGPUS)
+	 * by default (currently GFX8+ dGPUS and gfx9+ APUs).  Note that Raven1
+	 * did not support GPU reset, but newer variants do.
 	 */
-	if (family_id != AMDGPU_FAMILY_VI &&
-	    family_id != AMDGPU_FAMILY_AI &&
-	    family_id != AMDGPU_FAMILY_CI) {
+	if (family_id == AMDGPU_FAMILY_SI ||
+	    family_id == AMDGPU_FAMILY_KV ||
+	    family_id == AMDGPU_FAMILY_CZ ||
+	    family_id == AMDGPU_FAMILY_RV) {
 		printf("\n\nGPU reset is not enabled for the ASIC, deadlock suite disabled\n");
 		enable = CU_FALSE;
 	}
@@ -206,6 +210,8 @@ CU_TestInfo deadlock_tests[] = {
 	{ "compute ring bad slow dispatch test (set amdgpu.lockup_timeout=50,50)", amdgpu_dispatch_hang_slow_compute },
 	{ "gfx ring bad draw test (set amdgpu.lockup_timeout=50)", amdgpu_draw_hang_gfx },
 	{ "gfx ring slow bad draw test (set amdgpu.lockup_timeout=50)", amdgpu_draw_hang_slow_gfx },
+	{ "sdma ring corrupted header test (set amdgpu.lockup_timeout=50)", amdgpu_hang_sdma },
+	{ "sdma ring slow linear copy test (set amdgpu.lockup_timeout=50)", amdgpu_hang_slow_sdma },
 	CU_TEST_INFO_NULL,
 };
 
@@ -509,54 +515,182 @@ static void amdgpu_illegal_mem_access()
 
 static void amdgpu_dispatch_hang_gfx(void)
 {
-	amdgpu_dispatch_hang_helper(device_handle, AMDGPU_HW_IP_GFX);
+	amdgpu_test_dispatch_hang_helper(device_handle, AMDGPU_HW_IP_GFX);
 }
-
 static void amdgpu_dispatch_hang_compute(void)
 {
-	amdgpu_dispatch_hang_helper(device_handle, AMDGPU_HW_IP_COMPUTE);
+	amdgpu_test_dispatch_hang_helper(device_handle, AMDGPU_HW_IP_COMPUTE);
 }
-
 static void amdgpu_dispatch_hang_slow_gfx(void)
 {
-	amdgpu_dispatch_hang_slow_helper(device_handle, AMDGPU_HW_IP_GFX);
+	amdgpu_test_dispatch_hang_slow_helper(device_handle, AMDGPU_HW_IP_GFX);
 }
-
 static void amdgpu_dispatch_hang_slow_compute(void)
 {
-	amdgpu_dispatch_hang_slow_helper(device_handle, AMDGPU_HW_IP_COMPUTE);
+	amdgpu_test_dispatch_hang_slow_helper(device_handle, AMDGPU_HW_IP_COMPUTE);
 }
-
 static void amdgpu_draw_hang_gfx(void)
 {
-	int r;
-	struct drm_amdgpu_info_hw_ip info;
-	uint32_t ring_id;
+	amdgpu_test_draw_hang_helper(device_handle);
+}
+static void amdgpu_draw_hang_slow_gfx(void)
+{
+	amdgpu_test_draw_hang_slow_helper(device_handle);
+}
 
-	r = amdgpu_query_hw_ip_info(device_handle, AMDGPU_HW_IP_GFX, 0, &info);
+#define DMA_CORRUPTED_HEADER_HANG	1
+#define DMA_SLOW_LINEARCOPY_HANG	2
+
+static void amdgpu_hang_sdma_helper(unsigned hang_type)
+{
+	const int sdma_write_length = 1024;
+	amdgpu_context_handle context_handle;
+	amdgpu_bo_handle ib_result_handle;
+	amdgpu_bo_handle bo1, bo2;
+	amdgpu_bo_handle resources[3];
+	amdgpu_bo_list_handle bo_list;
+	void *ib_result_cpu;
+	struct amdgpu_cs_ib_info ib_info;
+	struct amdgpu_cs_request ibs_request;
+	struct amdgpu_cs_fence fence_status;
+	uint64_t bo1_mc, bo2_mc;
+	uint64_t ib_result_mc_address;
+	volatile unsigned char *bo1_cpu, *bo2_cpu;
+	amdgpu_va_handle bo1_va_handle, bo2_va_handle;
+	amdgpu_va_handle va_handle;
+	struct drm_amdgpu_info_hw_ip hw_ip_info;
+	int i, j, r;
+	uint32_t expired, ib_size;
+
+	r = amdgpu_query_hw_ip_info(device_handle, AMDGPU_HW_IP_DMA, 0, &hw_ip_info);
 	CU_ASSERT_EQUAL(r, 0);
-	if (!info.available_rings)
-		printf("SKIP ... as there's no graphic ring\n");
 
-	for (ring_id = 0; (1 << ring_id) & info.available_rings; ring_id++) {
-		amdgpu_memcpy_draw_test(device_handle, ring_id, 0);
-		amdgpu_memcpy_draw_test(device_handle, ring_id, 1);
-		amdgpu_memcpy_draw_test(device_handle, ring_id, 0);
-	}
-}
+	r = amdgpu_cs_ctx_create(device_handle, &context_handle);
+	CU_ASSERT_EQUAL(r, 0);
 
-static void amdgpu_draw_hang_slow_gfx(void)
-{
-	struct drm_amdgpu_info_hw_ip info;
-	uint32_t ring_id;
-	int r;
+	if (hang_type == DMA_CORRUPTED_HEADER_HANG)
+		ib_size = 4096;
+	else
+		ib_size = 4096 * 0x20000;
 
-	r = amdgpu_query_hw_ip_info(device_handle, AMDGPU_HW_IP_GFX, 0, &info);
+	r = amdgpu_bo_alloc_and_map(device_handle, ib_size, 4096,
+				    AMDGPU_GEM_DOMAIN_GTT, 0,
+				    &ib_result_handle, &ib_result_cpu,
+				    &ib_result_mc_address, &va_handle);
 	CU_ASSERT_EQUAL(r, 0);
 
-	for (ring_id = 0; (1 << ring_id) & info.available_rings; ring_id++) {
-		amdgpu_memcpy_draw_test(device_handle, ring_id, 0);
-		amdgpu_memcpy_draw_hang_slow_test(device_handle, ring_id);
-		amdgpu_memcpy_draw_test(device_handle, ring_id, 0);
+	r = amdgpu_bo_alloc_and_map(device_handle,
+				    sdma_write_length, 4096,
+				    AMDGPU_GEM_DOMAIN_GTT,
+				    0, &bo1,
+				    (void**)&bo1_cpu, &bo1_mc,
+				    &bo1_va_handle);
+	CU_ASSERT_EQUAL(r, 0);
+
+	/* set bo1 */
+	memset((void*)bo1_cpu, 0xaa, sdma_write_length);
+
+	/* allocate UC bo2 for sDMA use */
+	r = amdgpu_bo_alloc_and_map(device_handle,
+				    sdma_write_length, 4096,
+				    AMDGPU_GEM_DOMAIN_GTT,
+				    0, &bo2,
+				    (void**)&bo2_cpu, &bo2_mc,
+				    &bo2_va_handle);
+	CU_ASSERT_EQUAL(r, 0);
+
+	/* clear bo2 */
+	memset((void*)bo2_cpu, 0, sdma_write_length);
+
+	resources[0] = bo1;
+	resources[1] = bo2;
+	resources[2] = ib_result_handle;
+	r = amdgpu_bo_list_create(device_handle, 3,
+				  resources, NULL, &bo_list);
+
+	/* fulfill PM4: with bad copy linear header */
+	ptr = ib_result_cpu;
+	i = 0;
+	if (hang_type == DMA_CORRUPTED_HEADER_HANG) {
+		ptr[i++] = 0x23decd3d;
+		ptr[i++] = sdma_write_length - 1;
+		ptr[i++] = 0;
+		ptr[i++] = 0xffffffff & bo1_mc;
+		ptr[i++] = (0xffffffff00000000 & bo1_mc) >> 32;
+		ptr[i++] = 0xffffffff & bo2_mc;
+		ptr[i++] = (0xffffffff00000000 & bo2_mc) >> 32;
+	} else {
+		for (j = 1; j < 0x20000; j++) {
+			ptr[i++] = 0x1;
+			ptr[i++] = sdma_write_length - 1;
+			ptr[i++] = 0;
+			ptr[i++] = 0xffffffff & bo1_mc;
+			ptr[i++] = (0xffffffff00000000 & bo1_mc) >> 32;
+			ptr[i++] = 0xffffffff & bo2_mc;
+			ptr[i++] = (0xffffffff00000000 & bo2_mc) >> 32;
+			ptr[i++] = 0x1;
+			ptr[i++] = sdma_write_length - 1;
+			ptr[i++] = 0;
+			ptr[i++] = 0xffffffff & bo2_mc;
+			ptr[i++] = (0xffffffff00000000 & bo2_mc) >> 32;
+			ptr[i++] = 0xffffffff & bo1_mc;
+			ptr[i++] = (0xffffffff00000000 & bo1_mc) >> 32;
+		}
 	}
+
+	/* exec command */
+	memset(&ib_info, 0, sizeof(struct amdgpu_cs_ib_info));
+	ib_info.ib_mc_address = ib_result_mc_address;
+	ib_info.size = i;
+
+	memset(&ibs_request, 0, sizeof(struct amdgpu_cs_request));
+	ibs_request.ip_type = AMDGPU_HW_IP_DMA;
+	ibs_request.ring = 0;
+	ibs_request.number_of_ibs = 1;
+	ibs_request.ibs = &ib_info;
+	ibs_request.resources = bo_list;
+	ibs_request.fence_info.handle = NULL;
+
+	r = amdgpu_cs_submit(context_handle, 0, &ibs_request, 1);
+	CU_ASSERT_EQUAL(r, 0);
+
+	memset(&fence_status, 0, sizeof(struct amdgpu_cs_fence));
+	fence_status.context = context_handle;
+	fence_status.ip_type = AMDGPU_HW_IP_DMA;
+	fence_status.ip_instance = 0;
+	fence_status.ring = 0;
+	fence_status.fence = ibs_request.seq_no;
+
+	r = amdgpu_cs_query_fence_status(&fence_status,
+					 AMDGPU_TIMEOUT_INFINITE,
+					 0, &expired);
+	CU_ASSERT_EQUAL((r == 0 || r == -ECANCELED), 1);
+
+	r = amdgpu_bo_list_destroy(bo_list);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = amdgpu_bo_unmap_and_free(ib_result_handle, va_handle,
+				     ib_result_mc_address, 4096);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = amdgpu_bo_unmap_and_free(bo1, bo1_va_handle, bo1_mc,
+				     sdma_write_length);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = amdgpu_bo_unmap_and_free(bo2, bo2_va_handle, bo2_mc,
+				     sdma_write_length);
+	CU_ASSERT_EQUAL(r, 0);
+
+	/* end of test */
+	r = amdgpu_cs_ctx_free(context_handle);
+	CU_ASSERT_EQUAL(r, 0);
+}
+
+static void amdgpu_hang_sdma(void)
+{
+	amdgpu_hang_sdma_helper(DMA_CORRUPTED_HEADER_HANG);
+}
+static void amdgpu_hang_slow_sdma(void)
+{
+	amdgpu_hang_sdma_helper(DMA_SLOW_LINEARCOPY_HANG);
 }
diff --git a/tests/amdgpu/hotunplug_tests.c b/tests/amdgpu/hotunplug_tests.c
index 23ea1407..af933b19 100644
--- a/tests/amdgpu/hotunplug_tests.c
+++ b/tests/amdgpu/hotunplug_tests.c
@@ -62,15 +62,17 @@ CU_BOOL suite_hotunplug_tests_enable(void)
 		return CU_FALSE;
 	}
 
-	/* Disable until the hot-unplug support in kernel gets into drm-next */
-	if (major_version < 0xff)
-		enable = false;
-
 	if (amdgpu_device_initialize(drm_amdgpu[0], &major_version,
 					     &minor_version, &device_handle))
 		return CU_FALSE;
-
-	/* TODO Once DRM version for unplug feature ready compare here agains it*/
+	
+	/* Latest tested amdgpu version to work with all the tests */
+        if (minor_version < 46)
+                enable = false;
+
+        /* skip hotplug test on APUs */
+        if(device_handle->dev_info.ids_flags & AMDGPU_IDS_FLAGS_FUSION)
+                enable = false;
 
 	if (amdgpu_device_deinitialize(device_handle))
 		return CU_FALSE;
diff --git a/tests/amdgpu/jpeg_tests.c b/tests/amdgpu/jpeg_tests.c
index 5e50bef6..eccbfeb1 100644
--- a/tests/amdgpu/jpeg_tests.c
+++ b/tests/amdgpu/jpeg_tests.c
@@ -179,12 +179,9 @@ CU_BOOL suite_jpeg_tests_enable(void)
 		return CU_FALSE;
 	}
 
-	if (family_id == AMDGPU_FAMILY_RV) {
-		if (chip_id >= (chip_rev + 0x91))
-			jpeg_direct_reg = true;
-		else
-			jpeg_direct_reg = false;
-	} else if (family_id == AMDGPU_FAMILY_NV)
+	if (info.hw_ip_version_major == 1)
+		jpeg_direct_reg = false;
+	else if (info.hw_ip_version_major > 1 && info.hw_ip_version_major <= 4)
 		jpeg_direct_reg = true;
 	else
 		return CU_FALSE;
diff --git a/tests/amdgpu/meson.build b/tests/amdgpu/meson.build
index e027bccc..8618f6a1 100644
--- a/tests/amdgpu/meson.build
+++ b/tests/amdgpu/meson.build
@@ -25,7 +25,7 @@ if dep_cunit.found()
       'amdgpu_test.c', 'basic_tests.c', 'bo_tests.c', 'cs_tests.c',
       'vce_tests.c', 'uvd_enc_tests.c', 'vcn_tests.c', 'deadlock_tests.c',
       'vm_tests.c', 'ras_tests.c', 'syncobj_tests.c', 'security_tests.c',
-      'hotunplug_tests.c', 'jpeg_tests.c'
+      'hotunplug_tests.c', 'jpeg_tests.c', 'cp_dma_tests.c', 'shader_test_util.c'
     ),
     dependencies : [dep_cunit, dep_threads, dep_atomic_ops],
     include_directories : [inc_root, inc_drm, include_directories('../../amdgpu')],
diff --git a/tests/amdgpu/shader_code.h b/tests/amdgpu/shader_code.h
new file mode 100644
index 00000000..164c6193
--- /dev/null
+++ b/tests/amdgpu/shader_code.h
@@ -0,0 +1,153 @@
+/*
+ * Copyright 2022 Advanced Micro Devices, Inc.
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ *
+*/
+
+#ifndef _shader_code_h_
+#define _shader_code_h_
+
+#ifndef ARRAY_SIZE
+#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
+#endif
+
+enum amdgpu_test_gfx_version {
+	AMDGPU_TEST_GFX_V9 = 0,
+	AMDGPU_TEST_GFX_V10,
+	AMDGPU_TEST_GFX_V11,
+	AMDGPU_TEST_GFX_MAX,
+};
+
+enum cs_type {
+	CS_BUFFERCLEAR = 0,
+	CS_BUFFERCOPY,
+	CS_HANG,
+	CS_HANG_SLOW,
+};
+
+enum ps_type {
+	PS_CONST,
+	PS_TEX,
+	PS_HANG,
+	PS_HANG_SLOW
+};
+
+enum vs_type {
+	VS_RECTPOSTEXFAST,
+};
+
+struct reg_info {
+	uint32_t reg_offset;			///< Memory mapped register offset
+	uint32_t reg_value;			///< register value
+};
+
+#include "shader_code_hang.h"
+#include "shader_code_gfx9.h"
+#include "shader_code_gfx10.h"
+#include "shader_code_gfx11.h"
+
+struct shader_test_cs_shader {
+	const uint32_t *shader;
+	uint32_t shader_size;
+	const struct reg_info *sh_reg;
+	uint32_t num_sh_reg;
+	const struct reg_info *context_reg;
+	uint32_t num_context_reg;
+};
+
+struct shader_test_ps_shader {
+	const uint32_t *shader;
+	unsigned shader_size;
+	uint32_t patchinfo_code_size;
+	const uint32_t *patchinfo_code;
+	const uint32_t *patchinfo_code_offset;
+	const struct reg_info *sh_reg;
+	uint32_t num_sh_reg;
+	const struct reg_info *context_reg;
+	uint32_t num_context_reg;
+};
+
+struct shader_test_vs_shader {
+	const uint32_t *shader;
+	uint32_t shader_size;
+	const struct reg_info *sh_reg;
+	uint32_t num_sh_reg;
+	const struct reg_info *context_reg;
+	uint32_t num_context_reg;
+};
+
+static const struct shader_test_cs_shader shader_test_cs[AMDGPU_TEST_GFX_MAX][2] = {
+	// gfx9, cs_bufferclear
+	{{bufferclear_cs_shader_gfx9, sizeof(bufferclear_cs_shader_gfx9), bufferclear_cs_shader_registers_gfx9, ARRAY_SIZE(bufferclear_cs_shader_registers_gfx9)},
+	// gfx9, cs_buffercopy
+	{buffercopy_cs_shader_gfx9, sizeof(buffercopy_cs_shader_gfx9), bufferclear_cs_shader_registers_gfx9, ARRAY_SIZE(bufferclear_cs_shader_registers_gfx9)}},
+	// gfx10, cs_bufferclear
+	{{bufferclear_cs_shader_gfx10, sizeof(bufferclear_cs_shader_gfx10), bufferclear_cs_shader_registers_gfx9, ARRAY_SIZE(bufferclear_cs_shader_registers_gfx9)},
+	// gfx10, cs_buffercopy
+	{buffercopy_cs_shader_gfx10, sizeof(bufferclear_cs_shader_gfx10), bufferclear_cs_shader_registers_gfx9, ARRAY_SIZE(bufferclear_cs_shader_registers_gfx9)}},
+	// gfx11, cs_bufferclear
+	{{bufferclear_cs_shader_gfx11, sizeof(bufferclear_cs_shader_gfx11), bufferclear_cs_shader_registers_gfx11, ARRAY_SIZE(bufferclear_cs_shader_registers_gfx11)},
+	// gfx11, cs_buffercopy
+	{buffercopy_cs_shader_gfx11, sizeof(bufferclear_cs_shader_gfx11), bufferclear_cs_shader_registers_gfx11, ARRAY_SIZE(bufferclear_cs_shader_registers_gfx11)}},
+};
+
+#define SHADER_PS_INFO(_ps, _n) \
+	{ps_##_ps##_shader_gfx##_n, sizeof(ps_##_ps##_shader_gfx##_n), \
+	ps_##_ps##_shader_patchinfo_code_size_gfx##_n, \
+	&(ps_##_ps##_shader_patchinfo_code_gfx##_n)[0][0][0], \
+	ps_##_ps##_shader_patchinfo_offset_gfx##_n, \
+	ps_##_ps##_sh_registers_gfx##_n, ps_##_ps##_num_sh_registers_gfx##_n, \
+	ps_##_ps##_context_registers_gfx##_n, ps_##_ps##_num_context_registers_gfx##_n}
+static const struct shader_test_ps_shader shader_test_ps[AMDGPU_TEST_GFX_MAX][2] = {
+	{SHADER_PS_INFO(const, 9), SHADER_PS_INFO(tex, 9)},
+	{SHADER_PS_INFO(const, 10), SHADER_PS_INFO(tex, 10)},
+	{SHADER_PS_INFO(const, 11), SHADER_PS_INFO(tex, 11)},
+};
+
+#define SHADER_VS_INFO(_vs, _n) \
+	{vs_##_vs##_shader_gfx##_n, sizeof(vs_##_vs##_shader_gfx##_n), \
+	vs_##_vs##_sh_registers_gfx##_n, vs_##_vs##_num_sh_registers_gfx##_n, \
+	vs_##_vs##_context_registers_gfx##_n, vs_##_vs##_num_context_registers_gfx##_n}
+static const struct shader_test_vs_shader shader_test_vs[AMDGPU_TEST_GFX_MAX][1] = {
+	{SHADER_VS_INFO(RectPosTexFast, 9)},
+	{SHADER_VS_INFO(RectPosTexFast, 10)},
+	{SHADER_VS_INFO(RectPosTexFast, 11)},
+};
+
+struct shader_test_gfx_info {
+	const uint32_t *preamble_cache;
+	uint32_t size_preamble_cache;
+	const uint32_t *cached_cmd;
+	uint32_t size_cached_cmd;
+	uint32_t sh_reg_base;
+	uint32_t context_reg_base;
+};
+
+#define SHADER_TEST_GFX_INFO(_n) \
+	preamblecache_gfx##_n, sizeof(preamblecache_gfx##_n), \
+	cached_cmd_gfx##_n, sizeof(cached_cmd_gfx##_n), \
+	sh_reg_base_gfx##_n, context_reg_base_gfx##_n
+
+static struct shader_test_gfx_info shader_test_gfx_info[AMDGPU_TEST_GFX_MAX] = {
+	{SHADER_TEST_GFX_INFO(9),},
+	{SHADER_TEST_GFX_INFO(10),},
+	{SHADER_TEST_GFX_INFO(11),},
+};
+#endif
diff --git a/tests/amdgpu/shader_code_gfx10.h b/tests/amdgpu/shader_code_gfx10.h
new file mode 100644
index 00000000..1e7c8f96
--- /dev/null
+++ b/tests/amdgpu/shader_code_gfx10.h
@@ -0,0 +1,202 @@
+/*
+ * Copyright 2022 Advanced Micro Devices, Inc.
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ *
+*/
+
+#ifndef _shader_code_gfx10_h_
+#define _shader_code_gfx10_h_
+
+static const uint32_t bufferclear_cs_shader_gfx10[] = {
+	0xD7460004, 0x04010C08, 0x7E000204, 0x7E020205,
+	0x7E040206, 0x7E060207, 0xE01C2000, 0x80000004,
+	0xBF810000
+};
+
+static const uint32_t buffercopy_cs_shader_gfx10[] = {
+	0xD7460001, 0x04010C08, 0xE00C2000, 0x80000201,
+	0xBF8C3F70, 0xE01C2000, 0x80010201, 0xBF810000
+};
+
+static const uint32_t ps_const_shader_gfx10[] = {
+    0x7E000200, 0x7E020201, 0x7E040202, 0x7E060203,
+    0x5E000300, 0x5E020702, 0xBF800000, 0xBF800000,
+    0xF8001C0F, 0x00000100, 0xBF810000
+};
+
+#define ps_const_shader_patchinfo_code_size_gfx10 6
+
+static const uint32_t ps_const_shader_patchinfo_code_gfx10[][10][6] = {
+    {{ 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001890, 0x00000000 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001801, 0x00000000 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001803, 0x00000100 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001803, 0x00000300 },
+     { 0x5E000300, 0x5E020702, 0xBF800000, 0xBF800000, 0xF8001C0F, 0x00000100 },
+     { 0xD7690000, 0x00020300, 0xD7690001, 0x00020702, 0xF8001C0F, 0x00000100 },
+     { 0xD7680000, 0x00020300, 0xD7680001, 0x00020702, 0xF8001C0F, 0x00000100 },
+     { 0xD76A0000, 0x00020300, 0xD76A0001, 0x00020702, 0xF8001C0F, 0x00000100 },
+     { 0xD76B0000, 0x00020300, 0xD76B0001, 0x00020702, 0xF8001C0F, 0x00000100 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF800180F, 0x03020100 }
+    }
+};
+
+static const uint32_t ps_const_shader_patchinfo_offset_gfx10[] = {
+    0x00000004
+};
+
+#define ps_const_num_sh_registers_gfx10 2
+
+static const struct reg_info ps_const_sh_registers_gfx10[] = {
+	{0x2C0A, 0x000C0000},//{ mmSPI_SHADER_PGM_RSRC1_PS, 0x000C0000 },
+	{0x2C0B, 0x00000008}, //{ mmSPI_SHADER_PGM_RSRC2_PS, 0x00000008 }
+};
+
+static const struct reg_info ps_const_context_registers_gfx10[] =
+{
+    {0xA1B4, 0x00000002}, //{ mmSPI_PS_INPUT_ADDR,       0x00000002 },
+    {0xA1B6, 0x00000000}, //{ mmSPI_PS_IN_CONTROL,       0x00000000 },
+    {0xA08F, 0x0000000F}, //{ mmCB_SHADER_MASK,          0x0000000F },
+    {0xA203, 0x00000010}, //{ mmDB_SHADER_CONTROL,       0x00000010 },
+    {0xA1C4, 0x00000000}, //{ mmSPI_SHADER_Z_FORMAT,     0x00000000 },
+    {0xA1B8, 0x00000000}, //{ mmSPI_BARYC_CNTL,          0x00000000 /* Always 0 for now */},
+    {0xA1C5, 0x00000004}, //{ mmSPI_SHADER_COL_FORMAT,   0x00000004 /* SI_EXPORT_FMT_FP16_ABGR */ }
+};
+
+#define ps_const_num_context_registers_gfx10 7
+
+static const uint32_t ps_tex_shader_gfx10[] = {
+    0xBEFC030C, 0xBE8E047E, 0xBEFE0A7E, 0xC8080000,
+    0xC80C0100, 0xC8090001, 0xC80D0101, 0xF0800F0A,
+    0x00400402, 0x00000003, 0xBEFE040E, 0xBF8C0F70,
+    0x5E000B04, 0x5E020F06, 0xBF800000, 0xBF800000,
+    0xF8001C0F, 0x00000100, 0xBF810000
+};
+
+static const uint32_t ps_tex_shader_patchinfo_offset_gfx10[] = {
+    0x0000000C
+};
+
+#define ps_tex_shader_patchinfo_code_size_gfx10 6
+
+static const uint32_t ps_tex_shader_patchinfo_code_gfx10[][10][6] = {
+    {{ 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001890, 0x00000000 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001801, 0x00000004 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001803, 0x00000504 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8001803, 0x00000704 },
+     { 0x5E000B04, 0x5E020F06, 0xBF800000, 0xBF800000, 0xF8001C0F, 0x00000100 },
+     { 0xD7690000, 0x00020B04, 0xD7690001, 0x00020F06, 0xF8001C0F, 0x00000100 },
+     { 0xD7680000, 0x00020B04, 0xD7680001, 0x00020F06, 0xF8001C0F, 0x00000100 },
+     { 0xD76A0000, 0x00020B04, 0xD76A0001, 0x00020F06, 0xF8001C0F, 0x00000100 },
+     { 0xD76B0000, 0x00020B04, 0xD76B0001, 0x00020F06, 0xF8001C0F, 0x00000100 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF800180F, 0x07060504 }
+    }
+};
+
+static const struct reg_info ps_tex_sh_registers_gfx10[] =
+{
+     {0x2C0A, 0xc0081}, //0x020C0080 }, //{ mmSPI_SHADER_PGM_RSRC1_PS, 0x020C0080 },
+     {0x2C0B, 0x00000018 }, //{ mmSPI_SHADER_PGM_RSRC2_PS, 0x00000018 }
+};
+
+#define ps_tex_num_sh_registers_gfx10 2
+
+// Holds Context Register Information
+static const struct reg_info ps_tex_context_registers_gfx10[] =
+{
+    {0xA1B4, 0x00000002}, //{ mmSPI_PS_INPUT_ADDR,       0x00000002 },
+    {0xA1B6, 0x00000001}, //{ mmSPI_PS_IN_CONTROL,       0x00000001 },
+    {0xA08F, 0x0000000F}, //{ mmCB_SHADER_MASK,          0x0000000F },
+    {0xA203, 0x00000010}, //{ mmDB_SHADER_CONTROL,       0x00000010 },
+    {0xA1C4, 0x00000000}, //{ mmSPI_SHADER_Z_FORMAT,     0x00000000 },
+    {0xA1B8, 0x00000000}, //{ mmSPI_BARYC_CNTL,          0x00000000 /* Always 0 for now */},
+    {0xA1C5, 0x00000004}, //{ mmSPI_SHADER_COL_FORMAT,   0x00000004 /* SI_EXPORT_FMT_FP16_ABGR */ }
+};
+
+#define ps_tex_num_context_registers_gfx10 7
+
+static const uint32_t vs_RectPosTexFast_shader_gfx10[] = {
+    0x7E000B00, 0x060000F3, 0x7E020202, 0x7E040206,
+    0x7C040080, 0x060000F3, 0xD5010001, 0x01AA0200,
+    0x7E060203, 0xD5010002, 0x01AA0404, 0x7E080207,
+    0x7C040080, 0xD5010000, 0x01A80101, 0xD5010001,
+    0x01AA0601, 0x7E060208, 0x7E0A02F2, 0xD5010002,
+    0x01A80902, 0xD5010004, 0x01AA0805, 0x7E0C0209,
+    0xF80008CF, 0x05030100, 0xF800020F, 0x05060402,
+    0xBF810000
+};
+
+static const struct reg_info vs_RectPosTexFast_sh_registers_gfx10[] =
+{
+    {0x2C4A, 0x080C0041 }, //{ mmSPI_SHADER_PGM_RSRC1_VS, 0x080C0041 },
+    {0x2C4B, 0x00000018 }, //{ mmSPI_SHADER_PGM_RSRC2_VS, 0x00000018 }
+};
+
+#define vs_RectPosTexFast_num_sh_registers_gfx10 2
+
+// Holds Context Register Information
+static const struct reg_info vs_RectPosTexFast_context_registers_gfx10[] =
+{
+    {0xA1B1, 0x00000000}, //{ mmSPI_VS_OUT_CONFIG, 0x00000000 },
+    {0xA1C3, 0x00000000}, //{ mmSPI_SHADER_POS_FORMAT, 0x00000000 /* Always 0 for now */}
+};
+
+#define vs_RectPosTexFast_num_context_registers_gfx10 2
+
+static const uint32_t preamblecache_gfx10[] = {
+	0xc0026900, 0x81, 0x80000000, 0x40004000, 0xc0026900, 0x8c, 0xaa99aaaa, 0x0,
+	0xc0026900, 0x90, 0x80000000, 0x40004000, 0xc0026900, 0x94, 0x80000000, 0x40004000,
+	0xc0026900, 0xb4, 0x0, 0x3f800000, 0xc0016900, 0x103, 0x0,
+	0xc0016900, 0x208, 0x0, 0xc0016900, 0x290, 0x0,
+	0xc0016900, 0x2a1, 0x0, 0xc0026900, 0x2ad, 0x0, 0x0,
+	0xc0016900, 0x2d5, 0x10000, 0xc0016900, 0x2dc, 0x0,
+	0xc0066900, 0x2de, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0026900, 0x2e5, 0x0, 0x0,
+	0xc0056900, 0x2f9, 0x5, 0x3f800000, 0x3f800000, 0x3f800000, 0x3f800000,
+	0xc0046900, 0x310, 0, 0x3, 0, 0x100000, 0xc0026900, 0x316, 0xe, 0x20,
+	0xc0016900, 0x349, 0x0, 0xc0016900, 0x358, 0x0, 0xc0016900, 0x367, 0x0,
+	0xc0016900, 0x376, 0x0, 0xc0016900, 0x385, 0x0, 0xc0016900, 0x6, 0x0,
+	0xc0056900, 0xe8, 0x0, 0x0, 0x0, 0x0, 0x0,
+	0xc0076900, 0x1e1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
+	0xc0026900, 0x204, 0x90000, 0x4, 0xc0046900, 0x20c, 0x0, 0x0, 0x0, 0x0,
+	0xc0016900, 0x2b2, 0x0, 0xc0026900, 0x30e, 0xffffffff, 0xffffffff,
+	0xc0016900, 0x314, 0x0, 0xc0016900, 0x10a, 0, 0xc0016900, 0x2a6, 0, 0xc0016900, 0x210, 0,
+	0xc0016900, 0x2db, 0, 0xc0016900, 0x1d4, 0, 0xc0002f00, 0x1, 0xc0016900, 0x1, 0x1, 0xc0016900, 0xe, 0x2,
+	0xc0016900, 0x206, 0x300, 0xc0016900, 0x212, 0x200, 0xc0017900, 0x7b, 0x20, 0xc0017a00, 0x20000243, 0x0,
+	0xc0017900, 0x249, 0, 0xc0017900, 0x24a, 0, 0xc0017900, 0x24b, 0, 0xc0017900, 0x259, 0xffffffff,
+	0xc0017900, 0x25f, 0, 0xc0017900, 0x260, 0, 0xc0017900, 0x262, 0,
+	0xc0017600, 0x45, 0x0, 0xc0017600, 0x6, 0x0,
+	0xc0067600, 0x70, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
+	0xc0067600, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
+};
+
+static const uint32_t cached_cmd_gfx10[] = {
+	0xc0016900, 0x0, 0x0, 0xc0026900, 0x3, 0x2a, 0x0,
+	0xc0046900, 0xa, 0x0, 0x0, 0x0, 0x200020,
+	0xc0016900, 0x83, 0xffff, 0xc0026900, 0x8e, 0xf, 0xf,
+	0xc0056900, 0x105, 0x0, 0x0, 0x0, 0x0, 0x18,
+	0xc0026900, 0x10b, 0x0, 0x0, 0xc0016900, 0x1e0, 0x0,
+	0xc0036900, 0x200, 0x0, 0x10000, 0xcc0011,
+	0xc0026900, 0x292, 0x20, 0x6020000,
+	0xc0026900, 0x2b0, 0x0, 0x0, 0xc0016900, 0x2f8, 0x0
+};
+
+#define sh_reg_base_gfx10 0x2C00
+#define context_reg_base_gfx10 0xA000
+
+#endif
diff --git a/tests/amdgpu/shader_code_gfx11.h b/tests/amdgpu/shader_code_gfx11.h
new file mode 100644
index 00000000..8a998ae8
--- /dev/null
+++ b/tests/amdgpu/shader_code_gfx11.h
@@ -0,0 +1,320 @@
+/*
+ * Copyright 2022 Advanced Micro Devices, Inc.
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ *
+*/
+
+#ifndef _shader_code_gfx11_h_
+#define _shader_code_gfx11_h_
+
+static const uint32_t bufferclear_cs_shader_gfx11[] = {
+	0xB0802006, 0xBF840003, 0x360000FF, 0x000003FF,
+	0x7E020205, 0x7E040206, 0x7E060207, 0xBF870004,
+	0xD6460004, 0x04010C08, 0x7E000204, 0xE01C0000,
+	0x80800004, 0xBFB60003, 0xBFB00000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000
+};
+
+static const struct reg_info bufferclear_cs_shader_registers_gfx11[] = {
+	{0x2e12, 0x600C0041},	//{ mmCOMPUTE_PGM_RSRC1,	  0x600C0041 },
+	{0x2e13, 0x00000090},	//{ mmCOMPUTE_PGM_RSRC2,	  0x00000090 },
+	{0x2e07, 0x00000040},	//{ mmCOMPUTE_NUM_THREAD_X, 0x00000040 },
+	{0x2e08, 0x00000001},	//{ mmCOMPUTE_NUM_THREAD_Y, 0x00000001 },
+	{0x2e09, 0x00000001},	//{ mmCOMPUTE_NUM_THREAD_Z, 0x00000001 }
+};
+
+static const uint32_t buffercopy_cs_shader_gfx11[] = {
+	0xB0802006, 0xBF840003, 0x360000FF, 0x000003FF,
+	0xBF870001, 0xD6460001, 0x04010C08, 0xE00C0000,
+	0x80800201, 0xBF8903F7, 0xE01C0000, 0x80810201,
+	0xBFB60003, 0xBFB00000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000
+};
+
+static const uint32_t ps_const_shader_gfx11[] = {
+    0xB0802006, 0xBF840003, 0x7E000200, 0x7E020201,
+    0x7E040202, 0x7E060203, 0x5E000300, 0x5E020702,
+    0xBF800000, 0xBF800000, 0xF8000803, 0x00000100,
+    0xBFB00000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000
+};
+
+#define ps_const_shader_patchinfo_code_size_gfx11 6
+
+static const uint32_t ps_const_shader_patchinfo_code_gfx11[][10][6] = {
+	{{ 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8000890, 0x00000000 },  // SI_EXPORT_FMT_ZERO
+	{ 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8000801, 0x00000000 },  // SI_EXPORT_FMT_32_R
+	{ 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8000803, 0x00000100 },  // SI_EXPORT_FMT_32_GR
+	{ 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8000803, 0x00000300 },  // SI_EXPORT_FMT_32_AR
+	{ 0x5E000300, 0x5E020702, 0xBF800000, 0xBF800000, 0xF8000803, 0x00000100 },  // SI_EXPORT_FMT_FP16_ABGR
+	{ 0xD7220000, 0x00020300, 0xD7220001, 0x00020702, 0xF8000803, 0x00000100 },  // SI_EXPORT_FMT_UNORM16_ABGR
+	{ 0xD7210000, 0x00020300, 0xD7210001, 0x00020702, 0xF8000803, 0x00000100 },  // SI_EXPORT_FMT_SNORM16_ABGR
+	{ 0xD7230000, 0x00020300, 0xD7230001, 0x00020702, 0xF8000803, 0x00000100 },  // SI_EXPORT_FMT_uint32_t16_ABGR
+	{ 0xD7240000, 0x00020300, 0xD7240001, 0x00020702, 0xF8000803, 0x00000100 },  // SI_EXPORT_FMT_SINT16_ABGR
+	{ 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF800080F, 0x03020100 }   // SI_EXPORT_FMT_32_ABGR
+	}
+};
+
+static const uint32_t ps_const_shader_patchinfo_offset_gfx11[] = {
+	0x00000006
+};
+
+#define ps_const_num_sh_registers_gfx11 2
+
+static const struct reg_info ps_const_sh_registers_gfx11[] = {
+	{0x2C0A, 0x020C0000}, //{ mmSPI_SHADER_PGM_RSRC1_PS, 0x020C0000 },
+	{0x2C0B, 0x00000008}, //{ mmSPI_SHADER_PGM_RSRC2_PS, 0x00000008 }
+};
+
+static const struct reg_info ps_const_context_registers_gfx11[] = {
+	{0xA1B4, 0x00000002 }, //{ mmSPI_PS_INPUT_ADDR,       0x00000002 },
+	{0xA1B6, 0x00000000 }, //{ mmSPI_PS_IN_CONTROL,       0x00000000 },
+	{0xA08F, 0x0000000F }, //{ mmCB_SHADER_MASK,          0x0000000F },
+	{0xA203, 0x00000010 }, //{ mmDB_SHADER_CONTROL,       0x00000010 },
+	{0xA1C4, 0x00000000 }, //{ mmSPI_SHADER_Z_FORMAT,     0x00000000 },
+	{0xA1B8, 0x00000000 }, //{ mmSPI_BARYC_CNTL,          0x00000000 /* Always 0 for now */},
+	{0xA1C5, 0x00000004 }, //{ mmSPI_SHADER_COL_FORMAT,   0x00000004 /* SI_EXPORT_FMT_FP16_ABGR */ }
+};
+
+#define ps_const_num_context_registers_gfx11 7
+
+static const uint32_t ps_tex_shader_gfx11[] =
+{
+    0xB0802006, 0xBF840003, 0xBEFD000C, 0xBE8E017E,
+    0xBEFE1D7E, 0xCE000003, 0xCE000102, 0xCD000104,
+    0x040E0103, 0xCD000000, 0x040A0102, 0xBF870112,
+    0xCD010703, 0x04120303, 0xCD010700, 0x04020302,
+    0x8BFE0E7E, 0xF06C0F05, 0x08000003, 0x00000000,
+    0xBEFE010E, 0xBF8903F7, 0x5E000300, 0x5E020702,
+    0xBF800000, 0xBF800000, 0xF8000803, 0x00000100,
+    0xBFB00000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+    0xBF9F0000
+};
+
+static const uint32_t ps_tex_shader_patchinfo_offset_gfx11[] =
+{
+    0x00000016
+};
+
+// Denotes the Patch Info Code Length
+#define ps_tex_shader_patchinfo_code_size_gfx11 6
+
+static const uint32_t ps_tex_shader_patchinfo_code_gfx11[][10][6] =
+{
+    {{ 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8000890, 0x00000000 },  // SI_EXPORT_FMT_ZERO
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8000801, 0x00000000 },  // SI_EXPORT_FMT_32_R
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8000803, 0x00000100 },  // SI_EXPORT_FMT_32_GR
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF8000803, 0x00000300 },  // SI_EXPORT_FMT_32_AR
+     { 0x5E000300, 0x5E020702, 0xBF800000, 0xBF800000, 0xF8000803, 0x00000100 },  // SI_EXPORT_FMT_FP16_ABGR
+     { 0xD7220000, 0x00020300, 0xD7220001, 0x00020702, 0xF8000803, 0x00000100 },  // SI_EXPORT_FMT_UNORM16_ABGR
+     { 0xD7210000, 0x00020300, 0xD7210001, 0x00020702, 0xF8000803, 0x00000100 },  // SI_EXPORT_FMT_SNORM16_ABGR
+     { 0xD7230000, 0x00020300, 0xD7230001, 0x00020702, 0xF8000803, 0x00000100 },  // SI_EXPORT_FMT_uint32_t16_ABGR
+     { 0xD7240000, 0x00020300, 0xD7240001, 0x00020702, 0xF8000803, 0x00000100 },  // SI_EXPORT_FMT_SINT16_ABGR
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF800080F, 0x03020100 }   // SI_EXPORT_FMT_32_ABGR
+    }
+};
+// Holds Sh Register Information
+static const struct reg_info ps_tex_sh_registers_gfx11[] =
+{
+    {0x2C0A, 0x020C0081 }, //{ mmSPI_SHADER_PGM_RSRC1_PS, 0x020C0081 },
+    {0x2C0B, 0x00000018 } //{ mmSPI_SHADER_PGM_RSRC2_PS, 0x00000018 }
+};
+
+#define ps_tex_num_sh_registers_gfx11 2
+
+// Holds Context Register Information
+static const struct reg_info ps_tex_context_registers_gfx11[] =
+{
+    {0xA1B4, 0x00000002 }, //{ mmSPI_PS_INPUT_ADDR,       0x00000002 },
+    {0xA1B6, 0x00000001 }, //{ mmSPI_PS_IN_CONTROL,       0x00000001 },
+    {0xA08F, 0x0000000F }, //{ mmCB_SHADER_MASK,          0x0000000F },
+    {0xA203, 0x00000010 }, //{ mmDB_SHADER_CONTROL,       0x00000010 },
+    {0xA1C4, 0x00000000 }, //{ mmSPI_SHADER_Z_FORMAT,     0x00000000 },
+    {0xA1B8, 0x00000000 }, //{ mmSPI_BARYC_CNTL,          0x00000000 /* Always 0 for now */},
+    {0xA1C5, 0x00000004 } //{ mmSPI_SHADER_COL_FORMAT,   0x00000004 /* SI_EXPORT_FMT_FP16_ABGR */ }
+};
+
+#define ps_tex_num_context_registers_gfx11 7
+
+static const uint32_t vs_RectPosTexFast_shader_gfx11[] =
+{
+	0xB0802006, 0xBEFE01C1, 0xBF840003, 0xF408050A,
+	0xF80000B0, 0xD71F0001, 0x000100C1, 0x9300FF03,
+	0x00040018, 0x9301FF02, 0x0009000C, 0xBF870091,
+	0xD7200001, 0x000202C1, 0xD60B0001, 0x04058000,
+	0xBF870001, 0xD4490000, 0x00000301, 0xBE862100,
+	0x7E040B05, 0xBFA5001C, 0x7E06020A, 0x7E08020E,
+	0x7E0A020F, 0xBF8701B4, 0x060404F3, 0x7E140211,
+	0x7E0E0210, 0x7C240480, 0x060404F3, 0xD5010003,
+	0x01AA0608, 0xD5010004, 0x01AA080C, 0xBF870003,
+	0xD4120012, 0x00010102, 0x7E04020B, 0xBEEA1F12,
+	0xBF870483, 0xD5010008, 0x01AA080C, 0xD5010006,
+	0x01AA0608, 0xBF870003, 0xD5010004, 0x004A0409,
+	0xD5010009, 0x004A0A0D, 0xBEFE0106, 0x9302FF02,
+	0x00090016, 0xBF870009, 0xD4C9007E, 0x00000501,
+	0xBFA50002, 0xF8000941, 0x00000000, 0xBF89FFF0,
+	0x8BFE0006, 0xD71F0000, 0x000100C1, 0xBFA50013,
+	0x7E1602F2, 0x9300FF03, 0x00040018, 0x8B01FF05,
+	0x00007FFF, 0xBF8704B2, 0xD7200000, 0x000200C1,
+	0x7E0202F2, 0x84018901, 0x80018001, 0xBF870002,
+	0xD60B0000, 0x04018000, 0xF80008CF, 0x01070406,
+	0xBF89FC07, 0xE0744000, 0x01850800, 0xBFB00000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000,
+	0xBF9F0000, 0xBF9F0000, 0xBF9F0000, 0xBF9F0000
+};
+
+static const struct reg_info vs_RectPosTexFast_sh_registers_gfx11[] =
+{
+	{0x2C8A, 0x020C00C2}, //{ mmSPI_SHADER_PGM_RSRC1_GS, 0x020C00C2 },
+	{0x2C8B, 0x0008001C}, //{ mmSPI_SHADER_PGM_RSRC2_GS, 0x0008001C }
+};
+
+#define vs_RectPosTexFast_num_sh_registers_gfx11 2
+
+// Holds Context Register Information
+static const struct reg_info vs_RectPosTexFast_context_registers_gfx11[] =
+{
+	{0xA1B1, 0x00000000}, //{ mmSPI_VS_OUT_CONFIG, 0x00000000 },
+	{0xA1C2, 0x00000001}, //{ mmSPI_SHADER_IDX_FORMAT, 0x00000001 },
+	{0xA1C3, 0x00000000}, //{ mmSPI_SHADER_POS_FORMAT, 0x00000000 /* Always 0 for now */},
+	{0xA2E4, 0x00000000}, //{ mmVGT_GS_INSTANCE_CNT, 0x00000000 },
+	{0xA2AB, 0x00000004}, //{ mmVGT_ESGS_RING_ITEMSIZE, 0x00000004 },
+	{0xA2CE, 0x00000001}, //{ mmVGT_GS_MAX_VERT_OUT, 0x00000001 }
+};
+
+#define vs_RectPosTexFast_num_context_registers_gfx11 6
+
+static const uint32_t preamblecache_gfx11[] = {
+	0xc0026900, 0x81, 0x80000000, 0x40004000, 0xc0026900, 0x8c, 0xaa99aaaa, 0x0,
+	0xc0026900, 0x90, 0x80000000, 0x40004000, 0xc0026900, 0x94,  0x80000000, 0x40004000,
+	0xc0026900, 0xb4, 0x0, 0x3f800000, 0xc0016900, 0x103, 0x0, 0xc0016900, 0x208, 0x0,
+	0xc0016900, 0x2a1, 0x0, 0xc0016900,  0x2ad, 0x0, 0xc0016900, 0x2dc, 0x0,
+	0xc0066900, 0x2de, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
+	0xc0056900, 0x2f9, 0x5, 0x3f800000, 0x3f800000, 0x3f800000,  0x3f800000,
+	0xc0046900, 0x310, 0x0, 0x3, 0x0, 0x100000, 0xc0016900, 0x349, 0x0,
+	0xc0016900, 0x358, 0x0, 0xc0016900, 0x367, 0x0, 0xc0016900, 0x376,  0x0,
+	0xc0016900, 0x385, 0x0, 0xc0076900, 0x1e1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
+	0xc0026900, 0x204, 0x90000, 0x4, 0xc0016900, 0x20c, 0x0,  0xc0026900, 0x20e, 0x0, 0x0,
+	0xc0016900, 0x2b2, 0x0, 0xc0026900, 0x30e, 0xffffffff, 0xffffffff,
+	0xc0016900, 0x314, 0x0, 0xc0016900, 0x10a, 0x0,  0xc0016900, 0x2a6, 0x0,
+	0xc0016900, 0x210, 0x0, 0xc0016900, 0x2db, 0x0, 0xc0016900, 0x2e4, 0x0,
+	0xc0002f00, 0x1, 0xc0016900, 0x1, 0x0, 0xc0016900,  0x206, 0x300,
+	0xc0016900, 0x212, 0x200, 0xc0016900, 0xf4, 0x0, 0xc0016900, 0x18, 0x0,
+	0xc0016900, 0x1d4, 0xff, 0xc0016900, 0x2ce, 0x1, 0xc0016900, 0x2d3, 0x20001,
+	0xc0016900, 0x1ff, 0x80,  0xc0016900, 0x2d5, 0x6012010, 0xc0017a00, 0x20000243, 0x0,
+	0xc0017900, 0x249, 0x0, 0xc0017900, 0x24a, 0x0, 0xc0017900, 0x24b, 0x0,
+	0xc0017900,  0x259, 0xffffffff, 0xc0017900, 0x25f, 0x0, 0xc0017900, 0x260, 0x0,
+	0xc0017900, 0x262, 0x0, 0xc0017900, 0x444, 0x0, 0xc0017900, 0x445, 0x0,
+	0xc0017600, 0x6, 0x0, 0xc0017600, 0x80, 0x0, 0xc0017600, 0xb0, 0x0,
+	0xc0047600, 0xb2, 0x0, 0x0, 0x0, 0x0, 0xc0017600, 0x30, 0x0,
+	0xc0047600, 0x32, 0x0, 0x0, 0x0, 0x0
+};
+
+static const uint32_t cached_cmd_gfx11[] = {
+	0xc0016900, 0x0, 0x0, 0xc0026900, 0x3, 0x2a, 0x0,
+	0xc0046900, 0xa, 0x0, 0x0, 0x0, 0x200020,
+	0xc0016900, 0x83, 0xffff, 0xc0026900, 0x8e, 0xf, 0xf,
+	0xc0056900, 0x105, 0x0, 0x0, 0x0, 0x0, 0x0,
+	0xc0026900, 0x10b, 0x0, 0x0, 0xc0016900, 0x1e0, 0x0,
+	0xc0036900, 0x200, 0x0, 0x10000, 0xcc0011,
+	0xc0026900, 0x292, 0x20, 0x6020000,
+	0xc0026900, 0x2b0, 0x0, 0x0, 0xc0016900, 0x2f8, 0x0,
+	0xc0046900, 0x1d5, 0x0, 0x0, 0x0, 0x0, 0xc0016900, 0x104, 0x4a00005,
+	0xc0016900, 0x1f, 0xf2a0055, 0xc0017900, 0x266, 0x4
+};
+
+#define sh_reg_base_gfx11 0x2C00
+#define context_reg_base_gfx11 0xA000
+
+#endif
diff --git a/tests/amdgpu/shader_code_gfx9.h b/tests/amdgpu/shader_code_gfx9.h
new file mode 100644
index 00000000..1cb6582f
--- /dev/null
+++ b/tests/amdgpu/shader_code_gfx9.h
@@ -0,0 +1,205 @@
+/*
+ * Copyright 2022 Advanced Micro Devices, Inc.
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ *
+*/
+
+#ifndef _shader_code_gfx9_h_
+#define _shader_code_gfx9_h_
+
+static const uint32_t bufferclear_cs_shader_gfx9[] = {
+	0x260000ff, 0x000003ff, 0xd1fd0000, 0x04010c08,
+	0x7e020280, 0x7e040204, 0x7e060205, 0x7e080206,
+	0x7e0a0207, 0xe01c2000, 0x80000200, 0xbf8c0000,
+	0xbf810000
+};
+
+static const struct reg_info bufferclear_cs_shader_registers_gfx9[] = {
+	{0x2e12, 0x000C0041},	//{ mmCOMPUTE_PGM_RSRC1,	  0x000C0041 },
+	{0x2e13, 0x00000090},	//{ mmCOMPUTE_PGM_RSRC2,	  0x00000090 },
+	{0x2e07, 0x00000040},	//{ mmCOMPUTE_NUM_THREAD_X, 0x00000040 },
+	{0x2e08, 0x00000001},	//{ mmCOMPUTE_NUM_THREAD_Y, 0x00000001 },
+	{0x2e09, 0x00000001},	//{ mmCOMPUTE_NUM_THREAD_Z, 0x00000001 }
+};
+
+static const uint32_t buffercopy_cs_shader_gfx9[] = {
+	0x260000ff, 0x000003ff, 0xd1fd0000, 0x04010c08,
+	0x7e020280, 0xe00c2000, 0x80000200, 0xbf8c0f70,
+	0xe01c2000, 0x80010200, 0xbf810000
+};
+
+static const uint32_t ps_const_shader_gfx9[] = {
+	0x7E000200, 0x7E020201, 0x7E040202, 0x7E060203,
+	0xD2960000, 0x00020300, 0xD2960001, 0x00020702,
+	0xC4001C0F, 0x00000100, 0xBF810000
+};
+
+#define ps_const_shader_patchinfo_code_size_gfx9 6
+
+static const uint32_t ps_const_shader_patchinfo_code_gfx9[][10][6] = {
+    {{ 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xC4001890, 0x00000000 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xC4001801, 0x00000000 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xC4001803, 0x00000100 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xC4001803, 0x00000300 },
+     { 0xD2960000, 0x00020300, 0xD2960001, 0x00020702, 0xC4001C0F, 0x00000100 },
+     { 0xD2950000, 0x00020300, 0xD2950001, 0x00020702, 0xC4001C0F, 0x00000100 },
+     { 0xD2940000, 0x00020300, 0xD2940001, 0x00020702, 0xC4001C0F, 0x00000100 },
+     { 0xD2970000, 0x00020300, 0xD2970001, 0x00020702, 0xC4001C0F, 0x00000100 },
+     { 0xD2980000, 0x00020300, 0xD2980001, 0x00020702, 0xC4001C0F, 0x00000100 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xC400180F, 0x03020100 }
+    }
+};
+
+static const uint32_t ps_const_shader_patchinfo_offset_gfx9[] = {
+	0x00000004
+};
+
+#define ps_const_num_sh_registers_gfx9 2
+
+static const struct reg_info ps_const_sh_registers_gfx9[] = {
+	{0x2C0A, 0x000C0040},//{ mmSPI_SHADER_PGM_RSRC1_PS, 0x000C0040 },
+	{0x2C0B, 0x00000008}, //{ mmSPI_SHADER_PGM_RSRC2_PS, 0x00000008 }
+};
+
+#define ps_const_num_context_registers_gfx9 7
+
+static const struct reg_info ps_const_context_registers_gfx9[] = {
+    {0xA1B4, 0x00000002}, //{ mmSPI_PS_INPUT_ADDR,       0x00000002 },
+    {0xA1B6, 0x00000000}, //{ mmSPI_PS_IN_CONTROL,       0x00000000 },
+    {0xA08F, 0x0000000F}, //{ mmCB_SHADER_MASK,          0x0000000F },
+    {0xA203, 0x00000010}, //{ mmDB_SHADER_CONTROL,       0x00000010 },
+    {0xA1C4, 0x00000000}, //{ mmSPI_SHADER_Z_FORMAT,     0x00000000 },
+    {0xA1B8, 0x00000000}, //{ mmSPI_BARYC_CNTL,          0x00000000 /* Always 0 for now */},
+    {0xA1C5, 0x00000004}, //{ mmSPI_SHADER_COL_FORMAT,   0x00000004 }
+};
+
+static const uint32_t ps_tex_shader_gfx9[] = {
+    0xBEFC000C, 0xBE8E017E, 0xBEFE077E, 0xD4180000,
+    0xD4190001, 0xD41C0100, 0xD41D0101, 0xF0800F00,
+    0x00400206, 0xBEFE010E, 0xBF8C0F70, 0xD2960000,
+    0x00020702, 0xD2960001, 0x00020B04, 0xC4001C0F,
+    0x00000100, 0xBF810000
+};
+
+static const uint32_t ps_tex_shader_patchinfo_offset_gfx9[] = {
+    0x0000000B
+};
+
+#define ps_tex_shader_patchinfo_code_size_gfx9 6
+
+static const uint32_t ps_tex_shader_patchinfo_code_gfx9[][10][6] = {
+    {{ 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xC4001890, 0x00000000 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xC4001801, 0x00000002 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xC4001803, 0x00000302 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xC4001803, 0x00000502 },
+     { 0xD2960000, 0x00020702, 0xD2960001, 0x00020B04, 0xC4001C0F, 0x00000100 },
+     { 0xD2950000, 0x00020702, 0xD2950001, 0x00020B04, 0xC4001C0F, 0x00000100 },
+     { 0xD2940000, 0x00020702, 0xD2940001, 0x00020B04, 0xC4001C0F, 0x00000100 },
+     { 0xD2970000, 0x00020702, 0xD2970001, 0x00020B04, 0xC4001C0F, 0x00000100 },
+     { 0xD2980000, 0x00020702, 0xD2980001, 0x00020B04, 0xC4001C0F, 0x00000100 },
+     { 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xC400180F, 0x05040302 }
+    }
+};
+
+#define ps_tex_num_sh_registers_gfx9 2
+
+static const struct reg_info ps_tex_sh_registers_gfx9[] = {
+    {0x2C0A, 0x000C0081},//{ mmSPI_SHADER_PGM_RSRC1_PS, 0x000C0081 },
+    {0x2C0B, 0x00000018}, //{ mmSPI_SHADER_PGM_RSRC2_PS, 0x00000018 }
+};
+
+#define ps_tex_num_context_registers_gfx9 7
+
+static const struct reg_info ps_tex_context_registers_gfx9[] = {
+    {0xA1B4, 0x00000002}, //{ mmSPI_PS_INPUT_ADDR,       0x00000002 },
+    {0xA1B6, 0x00000001}, //{ mmSPI_PS_IN_CONTROL,       0x00000001 },
+    {0xA08F, 0x0000000F}, //{ mmCB_SHADER_MASK,          0x0000000F },
+    {0xA203, 0x00000010}, //{ mmDB_SHADER_CONTROL,       0x00000010 },
+    {0xA1C4, 0x00000000}, //{ mmSPI_SHADER_Z_FORMAT,     0x00000000 },
+    {0xA1B8, 0x00000000}, //{ mmSPI_BARYC_CNTL,          0x00000000 /* Always 0 for now */},
+    {0xA1C5, 0x00000004}, //{ mmSPI_SHADER_COL_FORMAT,   0x00000004  }
+};
+
+static const uint32_t vs_RectPosTexFast_shader_gfx9[] = {
+    0x7E000B00, 0x020000F3, 0xD042000A, 0x00010100,
+    0x7E020202, 0x7E040200, 0x020000F3, 0x7E060206,
+    0x7E080204, 0xD1000001, 0x002A0302, 0x7C840080,
+    0x7E000200, 0x7E040203, 0x7E0A0201, 0xD1000003,
+    0x002A0704, 0x7E0C0207, 0x7E0E0205, 0x00000101,
+    0x00020505, 0x7E040208, 0x7E0A02F2, 0x00060903,
+    0x00080D07, 0x7E0C0209, 0xC40008CF, 0x05020100,
+    0xC400020F, 0x05060403, 0xBF810000
+};
+
+static const struct reg_info vs_RectPosTexFast_sh_registers_gfx9[] =
+{
+    {0x2C4A, 0x000C0081}, //{ mmSPI_SHADER_PGM_RSRC1_VS, 0x000C0081 },
+    {0x2C4B, 0x00000018}, //{ mmSPI_SHADER_PGM_RSRC2_VS, 0x00000018 }
+};
+
+#define vs_RectPosTexFast_num_sh_registers_gfx9 2
+
+// Holds Context Register Information
+static const struct reg_info vs_RectPosTexFast_context_registers_gfx9[] =
+{
+    {0xA1B1, 0x00000000}, //{ mmSPI_VS_OUT_CONFIG, 0x00000000 },
+    {0xA1C3, 0x00000000}, //{ mmSPI_SHADER_POS_FORMAT, 0x00000000 /* Always 0 for now */}
+};
+
+#define vs_RectPosTexFast_num_context_registers_gfx9 2
+
+static const uint32_t preamblecache_gfx9[] = {
+	0xc0026900, 0x81, 0x80000000, 0x40004000, 0xc0026900, 0x8c, 0xaa99aaaa, 0x0,
+	0xc0026900, 0x90, 0x80000000, 0x40004000, 0xc0026900, 0x94, 0x80000000, 0x40004000,
+	0xc0026900, 0xb4,  0x0, 0x3f800000, 0xc0016900, 0x103, 0x0,
+	0xc0016900, 0x208, 0x0, 0xc0016900, 0x290, 0x0,
+	0xc0016900, 0x2a1, 0x0, 0xc0026900, 0x2ad, 0x0, 0x0,
+	0xc0016900, 0x2d5, 0x10000, 0xc0016900,  0x2dc, 0x0,
+	0xc0066900, 0x2de, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0026900, 0x2e5, 0x0, 0x0,
+	0xc0056900, 0x2f9, 0x5, 0x3f800000, 0x3f800000, 0x3f800000, 0x3f800000,
+	0xc0036900, 0x311, 0x3, 0, 0x100000, 0xc0026900, 0x316, 0x1e, 0x20,
+	0xc0016900, 0x349, 0x0, 0xc0016900, 0x358, 0x0, 0xc0016900, 0x367, 0x0,
+	0xc0016900, 0x376, 0x0, 0xc0016900, 0x385, 0x0, 0xc0016900, 0x19, 0x0,
+	0xc0056900, 0xe8, 0x0, 0x0, 0x0, 0x0, 0x0,
+	0xc0076900, 0x1e1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
+	0xc0026900, 0x204, 0x90000, 0x4, 0xc0046900, 0x20c, 0x0, 0x0, 0x0, 0x0,
+	0xc0016900, 0x2b2, 0x0, 0xc0026900, 0x30e, 0xffffffff, 0xffffffff,
+	0xc0016900, 0x314, 0x0, 0xc0016900, 0x2a6, 0, 0xc0016900, 0x210, 0,
+	0xc0002f00, 0x1, 0xc0016900, 0x1, 0x1,
+	0xc0016900, 0x18, 0x2, 0xc0016900, 0x206, 0x300, 0xc0017900, 0x20000243, 0x0,
+	0xc0017900, 0x248, 0xffffffff, 0xc0017900, 0x249, 0x0, 0xc0017900, 0x24a, 0x0,
+	0xc0017900, 0x24b, 0x0
+};
+
+static const uint32_t cached_cmd_gfx9[] = {
+	0xc0016900, 0x0, 0x0, 0xc0026900, 0x3, 0x2a, 0x0,
+	0xc0046900, 0xa, 0x0, 0x0, 0x0, 0x200020,
+	0xc0016900, 0x83, 0xffff, 0xc0026900, 0x8e, 0xf, 0xf,
+	0xc0056900, 0x105, 0x0, 0x0,  0x0, 0x0, 0x12,
+	0xc0026900, 0x10b, 0x0, 0x0, 0xc0016900, 0x1e0, 0x0,
+	0xc0036900, 0x200, 0x0, 0x10000, 0xcc0011,
+	0xc0026900, 0x292, 0x20, 0x60201b8,
+	0xc0026900, 0x2b0, 0x0, 0x0, 0xc0016900, 0x2f8, 0x0
+};
+
+#define sh_reg_base_gfx9 0x2C00
+#define context_reg_base_gfx9 0xA000
+
+#endif
diff --git a/tests/amdgpu/shader_code_hang.h b/tests/amdgpu/shader_code_hang.h
new file mode 100644
index 00000000..070bd718
--- /dev/null
+++ b/tests/amdgpu/shader_code_hang.h
@@ -0,0 +1,104 @@
+/*
+ * Copyright 2022 Advanced Micro Devices, Inc.
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ *
+*/
+
+#ifndef _shader_code_hang_h_
+#define _shader_code_hang_h_
+
+static const unsigned int memcpy_shader_hang[] = {
+        0xFFFFFFFF, 0xBEFE0A7E, 0xBEFC0304, 0xC0C20100,
+        0xC0800300, 0xC8080000, 0xC80C0100, 0xC8090001,
+        0xC80D0101, 0xBF8C007F, 0xF0800F00, 0x00010002,
+        0xBEFE040C, 0xBF8C0F70, 0xBF800000, 0xBF800000,
+        0xF800180F, 0x03020100, 0xBF810000
+};
+
+struct shader_test_shader_bin {
+	const uint32_t *shader;
+	uint32_t header_length;
+	uint32_t body_length;
+	uint32_t foot_length;
+};
+
+static const unsigned int memcpy_cs_hang_slow_ai_codes[] = {
+    0xd1fd0000, 0x04010c08, 0xe00c2000, 0x80000100,
+    0xbf8c0f70, 0xe01c2000, 0x80010100, 0xbf810000
+};
+
+static struct shader_test_shader_bin memcpy_cs_hang_slow_ai = {
+        memcpy_cs_hang_slow_ai_codes, 4, 3, 1
+};
+
+static const unsigned int memcpy_cs_hang_slow_rv_codes[] = {
+    0x8e00860c, 0x32000000, 0xe00c2000, 0x80010100,
+    0xbf8c0f70, 0xe01c2000, 0x80020100, 0xbf810000
+};
+
+static struct shader_test_shader_bin memcpy_cs_hang_slow_rv = {
+        memcpy_cs_hang_slow_rv_codes, 4, 3, 1
+};
+
+static const unsigned int memcpy_cs_hang_slow_nv_codes[] = {
+    0xd7460000, 0x04010c08, 0xe00c2000, 0x80000100,
+    0xbf8c0f70, 0xe01ca000, 0x80010100, 0xbf810000
+};
+
+static struct shader_test_shader_bin memcpy_cs_hang_slow_nv = {
+        memcpy_cs_hang_slow_nv_codes, 4, 3, 1
+};
+
+
+static const unsigned int memcpy_ps_hang_slow_ai_codes[] = {
+	0xbefc000c, 0xbe8e017e, 0xbefe077e, 0xd4080000,
+	0xd4090001, 0xd40c0100, 0xd40d0101, 0xf0800f00,
+	0x00400002, 0xbefe010e, 0xbf8c0f70, 0xbf800000,
+	0xbf800000, 0xbf800000, 0xbf800000, 0xc400180f,
+	0x03020100, 0xbf810000
+};
+
+static struct shader_test_shader_bin memcpy_ps_hang_slow_ai = {
+        memcpy_ps_hang_slow_ai_codes, 7, 2, 9
+};
+
+static const unsigned int memcpy_ps_hang_slow_navi10_codes[] = {
+	0xBEFC030C,0xBE8E047E,0xBEFE0A7E,0xC8080000,
+	0xC80C0100,0xC8090001,0xC80D0101,0xF0800F0A,
+	0x00400402,0x00000003,0xBEFE040E,0xBF8C0F70,
+	0xBF800000,0xBF800000,0xBF800000,0xBF800000,
+	0xF800180F,0x07060504,0xBF810000
+};
+
+static struct shader_test_shader_bin memcpy_ps_hang_slow_navi10 = {
+	memcpy_ps_hang_slow_navi10_codes, 7, 3, 9
+};
+
+static const unsigned int memcpy_ps_hang_slow_navi21_codes[] = {
+    0xBEFC030C, 0xBE8E047E, 0xBEFE0A7E, 0xC8080000, 0xC8000100, 0xC8090001, 0xC8010101, 0x87FE0E7E, // header
+    0xF0800F0A, 0x00400002, 0x00000000, // body - image_sample instruction
+    0xBFA3FFE3, 0xBEFE040E, 0xBF8C3F70, 0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000, 0xF800180F, 0x03020100, 0xBF810000 // footer
+};
+
+static struct shader_test_shader_bin memcpy_ps_hang_slow_navi21 = {
+	memcpy_ps_hang_slow_navi21_codes, 8, 3, 10
+};
+
+#endif
diff --git a/tests/amdgpu/shader_test_util.c b/tests/amdgpu/shader_test_util.c
new file mode 100644
index 00000000..8a19f59f
--- /dev/null
+++ b/tests/amdgpu/shader_test_util.c
@@ -0,0 +1,2184 @@
+#include <stdio.h>
+#include <stdlib.h>
+#include <unistd.h>
+#include <sys/types.h>
+#include <sys/stat.h>
+#include <string.h>
+#include <assert.h>
+
+#include "CUnit/Basic.h"
+#include "amdgpu_test.h"
+#include "shader_code.h"
+
+#define	PACKET3_DISPATCH_DIRECT				0x15
+#define PACKET3_CONTEXT_CONTROL                   0x28
+#define PACKET3_DRAW_INDEX_AUTO				0x2D
+#define PACKET3_SET_CONTEXT_REG				0x69
+#define PACKET3_SET_SH_REG                        0x76
+#define PACKET3_SET_SH_REG_OFFSET                       0x77
+#define PACKET3_SET_UCONFIG_REG				0x79
+#define PACKET3_SET_SH_REG_INDEX			0x9B
+
+#define	PACKET_TYPE3	3
+#define PACKET3(op, n)	((PACKET_TYPE3 << 30) |				\
+			 (((op) & 0xFF) << 8) |				\
+			 ((n) & 0x3FFF) << 16)
+#define PACKET3_COMPUTE(op, n) PACKET3(op, n) | (1 << 1)
+
+
+struct shader_test_bo {
+	amdgpu_bo_handle bo;
+	unsigned size;
+	unsigned heap;
+	void *ptr;
+	uint64_t mc_address;
+	amdgpu_va_handle va;
+};
+
+struct shader_test_draw {
+	struct shader_test_bo ps_bo;
+	enum ps_type ps_type;
+	struct shader_test_bo vs_bo;
+	enum vs_type vs_type;
+};
+struct shader_test_dispatch {
+	struct shader_test_bo cs_bo;
+	enum cs_type cs_type;
+};
+
+struct shader_test_info {
+	amdgpu_device_handle device_handle;
+	enum amdgpu_test_gfx_version version;
+	unsigned ip;
+	unsigned ring;
+	int hang;
+	int hang_slow;
+};
+
+struct shader_test_priv {
+	const struct shader_test_info *info;
+	unsigned cmd_curr;
+
+	union {
+		struct shader_test_draw shader_draw;
+		struct shader_test_dispatch shader_dispatch;
+	};
+	struct shader_test_bo vtx_attributes_mem;
+	struct shader_test_bo cmd;
+	struct shader_test_bo src;
+	struct shader_test_bo dst;
+};
+
+static int shader_test_bo_alloc(amdgpu_device_handle device_handle,
+					    struct shader_test_bo *shader_test_bo)
+{
+	return amdgpu_bo_alloc_and_map(device_handle, shader_test_bo->size, 4096,
+				    shader_test_bo->heap, 0,
+				    &(shader_test_bo->bo), (void **)&(shader_test_bo->ptr),
+				    &(shader_test_bo->mc_address), &(shader_test_bo->va));
+}
+
+static int shader_test_bo_free(struct shader_test_bo *shader_test_bo)
+{
+	return amdgpu_bo_unmap_and_free(shader_test_bo->bo, shader_test_bo->va,
+					shader_test_bo->mc_address,
+					shader_test_bo->size);
+}
+
+void shader_test_for_each(amdgpu_device_handle device_handle, unsigned ip,
+				       void (*fn)(struct shader_test_info *test_info))
+{
+	int r;
+	uint32_t ring_id;
+	struct shader_test_info test_info = {0};
+	struct drm_amdgpu_info_hw_ip info = {0};
+
+	r = amdgpu_query_hw_ip_info(device_handle, ip, 0, &info);
+	CU_ASSERT_EQUAL(r, 0);
+	if (!info.available_rings) {
+		printf("SKIP ... as there's no %s ring\n",
+				(ip == AMDGPU_HW_IP_GFX) ? "graphics": "compute");
+		return;
+	}
+
+	switch (info.hw_ip_version_major) {
+	case 9:
+		test_info.version = AMDGPU_TEST_GFX_V9;
+		break;
+	case 10:
+		test_info.version = AMDGPU_TEST_GFX_V10;
+		break;
+	case 11:
+		test_info.version = AMDGPU_TEST_GFX_V11;
+		break;
+	default:
+		printf("SKIP ... unsupported gfx version %d\n", info.hw_ip_version_major);
+		return;
+	}
+
+	test_info.device_handle = device_handle;
+	test_info.ip = ip;
+
+	printf("\n");
+	for (ring_id = 0; (1 << ring_id) & info.available_rings; ring_id++) {
+		printf("%s ring %d\n", (ip == AMDGPU_HW_IP_GFX) ? "graphics": "compute",
+					ring_id);
+		test_info.ring = ring_id;
+		fn(&test_info);
+	}
+}
+
+static void write_context_control(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+
+	if (test_priv->info->ip == AMDGPU_HW_IP_GFX) {
+		ptr[i++] = PACKET3(PACKET3_CONTEXT_CONTROL, 1);
+		ptr[i++] = 0x80000000;
+		ptr[i++] = 0x80000000;
+	}
+
+	test_priv->cmd_curr = i;
+}
+
+static void shader_test_load_shader_hang_slow(struct shader_test_bo *shader_bo,
+								   struct shader_test_shader_bin *shader_bin)
+{
+	int i, j, loop;
+
+	loop = (shader_bo->size / sizeof(uint32_t) - shader_bin->header_length
+		- shader_bin->foot_length) / shader_bin->body_length;
+
+	memcpy(shader_bo->ptr, shader_bin->shader, shader_bin->header_length * sizeof(uint32_t));
+
+	j = shader_bin->header_length;
+	for (i = 0; i < loop; i++) {
+		memcpy(shader_bo->ptr + j,
+			shader_bin->shader + shader_bin->header_length,
+			shader_bin->body_length * sizeof(uint32_t));
+		j += shader_bin->body_length;
+	}
+
+	memcpy(shader_bo->ptr + j,
+		shader_bin->shader + shader_bin->header_length + shader_bin->body_length,
+		shader_bin->foot_length * sizeof(uint32_t));
+}
+
+static void amdgpu_dispatch_load_cs_shader_hang_slow(struct shader_test_priv *test_priv)
+{
+	struct amdgpu_gpu_info gpu_info = {0};
+	struct shader_test_shader_bin *cs_shader_bin;
+	int r;
+
+	r = amdgpu_query_gpu_info(test_priv->info->device_handle, &gpu_info);
+	CU_ASSERT_EQUAL(r, 0);
+
+	switch (gpu_info.family_id) {
+	case AMDGPU_FAMILY_AI:
+		cs_shader_bin = &memcpy_cs_hang_slow_ai;
+		break;
+	case AMDGPU_FAMILY_RV:
+		cs_shader_bin = &memcpy_cs_hang_slow_rv;
+		break;
+	default:
+		cs_shader_bin = &memcpy_cs_hang_slow_nv;
+		break;
+	}
+
+	shader_test_load_shader_hang_slow(&test_priv->shader_dispatch.cs_bo, cs_shader_bin);
+}
+
+static void amdgpu_dispatch_load_cs_shader(struct shader_test_priv *test_priv)
+{
+	if (test_priv->info->hang) {
+		if (test_priv->info->hang_slow)
+			amdgpu_dispatch_load_cs_shader_hang_slow(test_priv);
+		else
+			memcpy(test_priv->shader_dispatch.cs_bo.ptr, memcpy_shader_hang,
+				sizeof(memcpy_shader_hang));
+	} else {
+		memcpy(test_priv->shader_dispatch.cs_bo.ptr,
+			shader_test_cs[test_priv->info->version][test_priv->shader_dispatch.cs_type].shader,
+			shader_test_cs[test_priv->info->version][test_priv->shader_dispatch.cs_type].shader_size);
+	}
+}
+
+static void amdgpu_dispatch_init_gfx9(struct shader_test_priv *test_priv)
+{
+	int i;
+	uint32_t *ptr = test_priv->cmd.ptr;
+
+	/* Write context control and load shadowing register if necessary */
+	write_context_control(test_priv);
+
+	i = test_priv->cmd_curr;
+
+	/* Issue commands to set default compute state. */
+	/* clear mmCOMPUTE_START_Z - mmCOMPUTE_START_X */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 3);
+	ptr[i++] = 0x204;
+	i += 3;
+
+	/* clear mmCOMPUTE_TMPRING_SIZE */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 1);
+	ptr[i++] = 0x218;
+	ptr[i++] = 0;
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_dispatch_init_gfx10(struct shader_test_priv *test_priv)
+{
+	int i;
+	uint32_t *ptr = test_priv->cmd.ptr;
+
+	amdgpu_dispatch_init_gfx9(test_priv);
+
+	i = test_priv->cmd_curr;
+
+	/* mmCOMPUTE_SHADER_CHKSUM */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 1);
+	ptr[i++] = 0x22a;
+	ptr[i++] = 0;
+	/* mmCOMPUTE_REQ_CTRL */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 6);
+	ptr[i++] = 0x222;
+	i += 6;
+	/* mmCP_COHER_START_DELAY */
+	ptr[i++] = PACKET3(PACKET3_SET_UCONFIG_REG, 1);
+	ptr[i++] = 0x7b;
+	ptr[i++] = 0x20;
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_dispatch_init_gfx11(struct shader_test_priv *test_priv)
+{
+	int i;
+	uint32_t *ptr = test_priv->cmd.ptr;
+
+	/* Write context control and load shadowing register if necessary */
+	write_context_control(test_priv);
+
+	i = test_priv->cmd_curr;
+
+	/* Issue commands to set default compute state. */
+	/* clear mmCOMPUTE_START_Z - mmCOMPUTE_START_X */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 3);
+	ptr[i++] = 0x204;
+	i += 3;
+
+	/* clear mmCOMPUTE_TMPRING_SIZE */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 1);
+	ptr[i++] = 0x218;
+	ptr[i++] = 0;
+
+	/* mmCOMPUTE_REQ_CTRL */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 1);
+	ptr[i++] = 0x222;
+	ptr[i++] = 0;
+
+	/* mmCOMPUTE_USER_ACCUM_0 .. 3*/
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+	ptr[i++] = 0x224;
+	i += 4;
+
+	/* mmCOMPUTE_SHADER_CHKSUM */
+	ptr[i++] = PACKET3(PACKET3_SET_UCONFIG_REG, 1);
+	ptr[i++] = 0x22a;
+	ptr[i++] = 0;
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_dispatch_init(struct shader_test_priv *test_priv)
+{
+	switch (test_priv->info->version) {
+	case AMDGPU_TEST_GFX_V9:
+		amdgpu_dispatch_init_gfx9(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_V10:
+		amdgpu_dispatch_init_gfx10(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_V11:
+		amdgpu_dispatch_init_gfx11(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_MAX:
+		assert(1 && "Not Support gfx, never go here");
+		break;
+	}
+}
+
+static void amdgpu_dispatch_write_cumask(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+
+	/*  Issue commands to set cu mask used in current dispatch */
+	switch (test_priv->info->version) {
+	case AMDGPU_TEST_GFX_V9:
+		/* set mmCOMPUTE_STATIC_THREAD_MGMT_SE1 - mmCOMPUTE_STATIC_THREAD_MGMT_SE0 */
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 2);
+		ptr[i++] = 0x216;
+		ptr[i++] = 0xffffffff;
+		ptr[i++] = 0xffffffff;
+		/* set mmCOMPUTE_STATIC_THREAD_MGMT_SE3 - mmCOMPUTE_STATIC_THREAD_MGMT_SE2 */
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 2);
+		ptr[i++] = 0x219;
+		ptr[i++] = 0xffffffff;
+		ptr[i++] = 0xffffffff;
+		break;
+	case AMDGPU_TEST_GFX_V10:
+	case AMDGPU_TEST_GFX_V11:
+		/* set mmCOMPUTE_STATIC_THREAD_MGMT_SE1 - mmCOMPUTE_STATIC_THREAD_MGMT_SE0 */
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG_INDEX, 2);
+		ptr[i++] = 0x30000216;
+		ptr[i++] = 0xffffffff;
+		ptr[i++] = 0xffffffff;
+		/* set mmCOMPUTE_STATIC_THREAD_MGMT_SE3 - mmCOMPUTE_STATIC_THREAD_MGMT_SE2 */
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG_INDEX, 2);
+		ptr[i++] = 0x30000219;
+		ptr[i++] = 0xffffffff;
+		ptr[i++] = 0xffffffff;
+		break;
+	case AMDGPU_TEST_GFX_MAX:
+		assert(1 && "Not Support gfx, never go here");
+		break;
+	}
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_dispatch_write2hw_gfx9(struct shader_test_priv *test_priv)
+{
+	const struct shader_test_cs_shader *cs_shader = &shader_test_cs[test_priv->info->version][test_priv->shader_dispatch.cs_type];
+	int j, i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+	uint64_t shader_addr = test_priv->shader_dispatch.cs_bo.mc_address;
+
+	/* Writes shader state to HW */
+	/* set mmCOMPUTE_PGM_HI - mmCOMPUTE_PGM_LO */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 2);
+	ptr[i++] = 0x20c;
+	ptr[i++] = (shader_addr >> 8);
+	ptr[i++] = (shader_addr >> 40);
+	/* write sh regs*/
+	for (j = 0; j < cs_shader->num_sh_reg; j++) {
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 1);
+		/* - Gfx9ShRegBase */
+		ptr[i++] = cs_shader->sh_reg[j].reg_offset - shader_test_gfx_info[test_priv->info->version].sh_reg_base;
+		ptr[i++] = cs_shader->sh_reg[j].reg_value;
+	}
+
+	/* Write constant data */
+	if (CS_BUFFERCLEAR == test_priv->shader_dispatch.cs_type) {
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+		ptr[i++] = 0x240;
+		ptr[i++] = test_priv->dst.mc_address;
+		ptr[i++] = (test_priv->dst.mc_address >> 32) | 0x100000;
+		ptr[i++] = test_priv->dst.size / 16;
+		ptr[i++] = 0x74fac;
+
+		/* Sets a range of pixel shader constants */
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+		ptr[i++] = 0x244;
+		ptr[i++] = 0x22222222;
+		ptr[i++] = 0x22222222;
+		ptr[i++] = 0x22222222;
+		ptr[i++] = 0x22222222;
+	} else {
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+		ptr[i++] = 0x240;
+		ptr[i++] = test_priv->src.mc_address;
+		ptr[i++] = (test_priv->src.mc_address >> 32) | 0x100000;
+		ptr[i++] = test_priv->src.size / 16;
+		ptr[i++] = 0x74fac;
+
+		/* Writes the UAV constant data to the SGPRs. */
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+		ptr[i++] = 0x244;
+		ptr[i++] = test_priv->dst.mc_address;
+		ptr[i++] = (test_priv->dst.mc_address >> 32) | 0x100000;
+		ptr[i++] = test_priv->dst.size / 16;
+		ptr[i++] = 0x74fac;
+	}
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_dispatch_write2hw_gfx10(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+	const struct shader_test_cs_shader *cs_shader = &shader_test_cs[test_priv->info->version][test_priv->shader_dispatch.cs_type];
+	int j;
+	uint64_t shader_addr = test_priv->shader_dispatch.cs_bo.mc_address;
+
+	/* Writes shader state to HW */
+	/* set mmCOMPUTE_PGM_HI - mmCOMPUTE_PGM_LO */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 2);
+	ptr[i++] = 0x20c;
+	ptr[i++] = (shader_addr >> 8);
+	ptr[i++] = (shader_addr >> 40);
+	/* write sh regs*/
+	for (j = 0; j < cs_shader->num_sh_reg; j++) {
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 1);
+		/* - Gfx9ShRegBase */
+		ptr[i++] = cs_shader->sh_reg[j].reg_offset - shader_test_gfx_info[test_priv->info->version].sh_reg_base;
+		ptr[i++] = cs_shader->sh_reg[j].reg_value;
+	}
+
+	/* mmCOMPUTE_PGM_RSRC3 */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 1);
+	ptr[i++] = 0x228;
+	ptr[i++] = 0;
+
+	if (CS_BUFFERCLEAR == test_priv->shader_dispatch.cs_type) {
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+		ptr[i++] = 0x240;
+		ptr[i++] = test_priv->dst.mc_address;
+		ptr[i++] = (test_priv->dst.mc_address >> 32) | 0x100000;
+		ptr[i++] = test_priv->dst.size / 16;
+		ptr[i++] = 0x1104bfac;
+
+		/* Sets a range of pixel shader constants */
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+		ptr[i++] = 0x244;
+		ptr[i++] = 0x22222222;
+		ptr[i++] = 0x22222222;
+		ptr[i++] = 0x22222222;
+		ptr[i++] = 0x22222222;
+	} else {
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+		ptr[i++] = 0x240;
+		ptr[i++] = test_priv->src.mc_address;
+		ptr[i++] = (test_priv->src.mc_address >> 32) | 0x100000;
+		ptr[i++] = test_priv->src.size / 16;
+		ptr[i++] = 0x1104bfac;
+
+		/* Writes the UAV constant data to the SGPRs. */
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+		ptr[i++] = 0x244;
+		ptr[i++] = test_priv->dst.mc_address;
+		ptr[i++] = (test_priv->dst.mc_address>> 32) | 0x100000;
+		ptr[i++] = test_priv->dst.size / 16;
+		ptr[i++] = 0x1104bfac;
+	}
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_dispatch_write2hw_gfx11(struct shader_test_priv *test_priv)
+{
+	enum amdgpu_test_gfx_version version = test_priv->info->version;
+	const struct shader_test_cs_shader *cs_shader = &shader_test_cs[version][test_priv->shader_dispatch.cs_type];
+	int j, i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+	uint64_t shader_addr = test_priv->shader_dispatch.cs_bo.mc_address;
+
+	/* Writes shader state to HW */
+	/* set mmCOMPUTE_PGM_HI - mmCOMPUTE_PGM_LO */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 2);
+	ptr[i++] = 0x20c;
+	ptr[i++] = (shader_addr >> 8);
+	ptr[i++] = (shader_addr >> 40);
+
+	/* write sh regs*/
+	for (j = 0; j < cs_shader->num_sh_reg; j++) {
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 1);
+		/* - Gfx9ShRegBase */
+		ptr[i++] = cs_shader->sh_reg[j].reg_offset - shader_test_gfx_info[version].sh_reg_base;
+		ptr[i++] = cs_shader->sh_reg[j].reg_value;
+		if (cs_shader->sh_reg[j].reg_offset == 0x2E12)
+			ptr[i-1] &= ~(1<<29);
+	}
+
+	/* mmCOMPUTE_PGM_RSRC3 */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 1);
+	ptr[i++] = 0x228;
+	ptr[i++] = 0x3f0;
+
+	/* Write constant data */
+	/* Writes the texture resource constants data to the SGPRs */
+	if (CS_BUFFERCLEAR == test_priv->shader_dispatch.cs_type) {
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+		ptr[i++] = 0x240;
+		ptr[i++] = test_priv->dst.mc_address;
+		ptr[i++] = (test_priv->dst.mc_address >> 32) | 0x100000;
+		ptr[i++] = test_priv->dst.size / 16;
+		ptr[i++] = 0x1003dfac;
+
+		/* Sets a range of pixel shader constants */
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+		ptr[i++] = 0x244;
+		ptr[i++] = 0x22222222;
+		ptr[i++] = 0x22222222;
+		ptr[i++] = 0x22222222;
+		ptr[i++] = 0x22222222;
+	} else {
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+		ptr[i++] = 0x240;
+		ptr[i++] = test_priv->src.mc_address;
+		ptr[i++] = (test_priv->src.mc_address >> 32) | 0x100000;
+		ptr[i++] = test_priv->src.size / 16;
+		ptr[i++] = 0x1003dfac;
+
+		/* Writes the UAV constant data to the SGPRs. */
+		ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 4);
+		ptr[i++] = 0x244;
+		ptr[i++] = test_priv->dst.mc_address;
+		ptr[i++] = (test_priv->dst.mc_address>> 32) | 0x100000;
+		ptr[i++] = test_priv->dst.size / 16;
+		ptr[i++] = 0x1003dfac;
+	}
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_dispatch_write2hw(struct shader_test_priv *test_priv)
+{
+	switch (test_priv->info->version) {
+	case AMDGPU_TEST_GFX_V9:
+		amdgpu_dispatch_write2hw_gfx9(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_V10:
+		amdgpu_dispatch_write2hw_gfx10(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_V11:
+		amdgpu_dispatch_write2hw_gfx11(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_MAX:
+		assert(1 && "Not Support gfx, never go here");
+		break;
+	}
+}
+
+static void amdgpu_dispatch_write_dispatch_cmd(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+
+	/* clear mmCOMPUTE_RESOURCE_LIMITS */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_SET_SH_REG, 1);
+	ptr[i++] = 0x215;
+	ptr[i++] = 0;
+
+	/* dispatch direct command */
+	ptr[i++] = PACKET3_COMPUTE(PACKET3_DISPATCH_DIRECT, 3);
+	ptr[i++] = (test_priv->dst.size / 16 + 0x40 - 1 ) / 0x40;//0x10;
+	ptr[i++] = 1;
+	ptr[i++] = 1;
+	ptr[i++] = 1;
+
+	test_priv->cmd_curr = i;
+}
+static void amdgpu_test_dispatch_memset(struct shader_test_info *test_info)
+{
+	amdgpu_context_handle context_handle;
+	amdgpu_bo_handle resources[3];
+	struct shader_test_priv test_priv;
+	struct shader_test_bo *cmd = &(test_priv.cmd);
+	struct shader_test_bo *dst = &(test_priv.dst);
+	struct shader_test_bo *shader = &(test_priv.shader_dispatch.cs_bo);
+	uint32_t *ptr_cmd;
+	uint8_t *ptr_dst;
+	int i, r;
+	struct amdgpu_cs_request ibs_request = {0};
+	struct amdgpu_cs_ib_info ib_info= {0};
+	amdgpu_bo_list_handle bo_list;
+	struct amdgpu_cs_fence fence_status = {0};
+	uint32_t expired;
+	uint8_t cptr[16];
+
+	memset(&test_priv, 0, sizeof(test_priv));
+	test_priv.info = test_info;
+	test_priv.shader_dispatch.cs_type = CS_BUFFERCLEAR;
+	r = amdgpu_cs_ctx_create(test_info->device_handle, &context_handle);
+	CU_ASSERT_EQUAL(r, 0);
+
+	cmd->size = 4096;
+	cmd->heap = AMDGPU_GEM_DOMAIN_GTT;
+	r = shader_test_bo_alloc(test_info->device_handle, cmd);
+	CU_ASSERT_EQUAL(r, 0);
+	ptr_cmd = cmd->ptr;
+	memset(ptr_cmd, 0, cmd->size);
+
+	shader->size = 4096;
+	shader->heap = AMDGPU_GEM_DOMAIN_VRAM;
+	r = shader_test_bo_alloc(test_info->device_handle, shader);
+	CU_ASSERT_EQUAL(r, 0);
+	memset(shader->ptr, 0, shader->size);
+	amdgpu_dispatch_load_cs_shader(&test_priv);
+
+	dst->size = 0x4000;
+	dst->heap = AMDGPU_GEM_DOMAIN_VRAM;
+	r = shader_test_bo_alloc(test_info->device_handle, dst);
+	CU_ASSERT_EQUAL(r, 0);
+
+	amdgpu_dispatch_init(&test_priv);
+
+	/*  Issue commands to set cu mask used in current dispatch */
+	amdgpu_dispatch_write_cumask(&test_priv);
+
+	/* Writes shader state to HW */
+	amdgpu_dispatch_write2hw(&test_priv);
+
+	amdgpu_dispatch_write_dispatch_cmd(&test_priv);
+
+	i = test_priv.cmd_curr;
+	while (i & 7)
+		ptr_cmd[i++] = 0xffff1000; /* type3 nop packet */
+	test_priv.cmd_curr = i;
+
+	resources[0] = dst->bo;
+	resources[1] = shader->bo;
+	resources[2] = cmd->bo;
+	r = amdgpu_bo_list_create(test_info->device_handle, 3, resources, NULL, &bo_list);
+	CU_ASSERT_EQUAL(r, 0);
+
+	ib_info.ib_mc_address = cmd->mc_address;
+	ib_info.size = test_priv.cmd_curr;
+	ibs_request.ip_type = test_info->ip;
+	ibs_request.ring = test_info->ring;
+	ibs_request.resources = bo_list;
+	ibs_request.number_of_ibs = 1;
+	ibs_request.ibs = &ib_info;
+	ibs_request.fence_info.handle = NULL;
+
+	/* submit CS */
+	r = amdgpu_cs_submit(context_handle, 0, &ibs_request, 1);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = amdgpu_bo_list_destroy(bo_list);
+	CU_ASSERT_EQUAL(r, 0);
+
+	fence_status.ip_type = test_info->ip;
+	fence_status.ip_instance = 0;
+	fence_status.ring = test_info->ring;
+	fence_status.context = context_handle;
+	fence_status.fence = ibs_request.seq_no;
+
+	/* wait for IB accomplished */
+	r = amdgpu_cs_query_fence_status(&fence_status,
+					 AMDGPU_TIMEOUT_INFINITE,
+					 0, &expired);
+	CU_ASSERT_EQUAL(r, 0);
+	CU_ASSERT_EQUAL(expired, true);
+
+	/* verify if memset test result meets with expected */
+	i = 0;
+	ptr_dst = (uint8_t *)(dst->ptr);
+	memset(cptr, 0x22, 16);
+	CU_ASSERT_EQUAL(memcmp(ptr_dst + i, cptr, 16), 0);
+	i = dst->size - 16;
+	CU_ASSERT_EQUAL(memcmp(ptr_dst + i, cptr, 16), 0);
+	i = dst->size / 2;
+	CU_ASSERT_EQUAL(memcmp(ptr_dst + i, cptr, 16), 0);
+
+	r = shader_test_bo_free(dst);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_free(shader);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_free(cmd);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = amdgpu_cs_ctx_free(context_handle);
+	CU_ASSERT_EQUAL(r, 0);
+}
+
+static
+void amdgpu_test_dispatch_memcpy(struct shader_test_info *test_info)
+{
+	struct shader_test_priv test_priv;
+	amdgpu_context_handle context_handle;
+	amdgpu_bo_handle resources[4];
+	struct shader_test_bo *cmd = &(test_priv.cmd);
+	struct shader_test_bo *src = &(test_priv.src);
+	struct shader_test_bo *dst = &(test_priv.dst);
+	struct shader_test_bo *shader = &(test_priv.shader_dispatch.cs_bo);
+	uint32_t *ptr_cmd;
+	uint8_t *ptr_src;
+	uint8_t *ptr_dst;
+	int i, r;
+	struct amdgpu_cs_request ibs_request = {0};
+	struct amdgpu_cs_ib_info ib_info= {0};
+	uint32_t expired, hang_state, hangs;
+	amdgpu_bo_list_handle bo_list;
+	struct amdgpu_cs_fence fence_status = {0};
+
+	memset(&test_priv, 0, sizeof(test_priv));
+	test_priv.info = test_info;
+	test_priv.cmd.size = 4096;
+	test_priv.cmd.heap = AMDGPU_GEM_DOMAIN_GTT;
+
+	test_priv.shader_dispatch.cs_bo.heap = AMDGPU_GEM_DOMAIN_VRAM;
+	test_priv.shader_dispatch.cs_type = CS_BUFFERCOPY;
+	test_priv.src.heap = AMDGPU_GEM_DOMAIN_VRAM;
+	test_priv.dst.heap = AMDGPU_GEM_DOMAIN_VRAM;
+	if (test_info->hang_slow) {
+		test_priv.shader_dispatch.cs_bo.size = 0x4000000;
+		test_priv.src.size = 0x4000000;
+		test_priv.dst.size = 0x4000000;
+	} else {
+		test_priv.shader_dispatch.cs_bo.size = 4096;
+		test_priv.src.size = 0x4000;
+		test_priv.dst.size = 0x4000;
+	}
+
+	r = amdgpu_cs_ctx_create(test_info->device_handle, &context_handle);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_alloc(test_info->device_handle, cmd);
+	CU_ASSERT_EQUAL(r, 0);
+	ptr_cmd = cmd->ptr;
+	memset(ptr_cmd, 0, cmd->size);
+
+	r = shader_test_bo_alloc(test_info->device_handle, shader);
+	CU_ASSERT_EQUAL(r, 0);
+	memset(shader->ptr, 0, shader->size);
+	amdgpu_dispatch_load_cs_shader(&test_priv);
+
+	r = shader_test_bo_alloc(test_info->device_handle, src);
+	CU_ASSERT_EQUAL(r, 0);
+	ptr_src = (uint8_t *)(src->ptr);
+	memset(ptr_src, 0x55, src->size);
+
+	r = shader_test_bo_alloc(test_info->device_handle, dst);
+	CU_ASSERT_EQUAL(r, 0);
+
+	amdgpu_dispatch_init(&test_priv);
+
+	/*  Issue commands to set cu mask used in current dispatch */
+	amdgpu_dispatch_write_cumask(&test_priv);
+
+	/* Writes shader state to HW */
+	amdgpu_dispatch_write2hw(&test_priv);
+
+	amdgpu_dispatch_write_dispatch_cmd(&test_priv);
+
+	i = test_priv.cmd_curr;
+	while (i & 7)
+		ptr_cmd[i++] = 0xffff1000; /* type3 nop packet */
+	test_priv.cmd_curr = i;
+
+	resources[0] = shader->bo;
+	resources[1] = src->bo;
+	resources[2] = dst->bo;
+	resources[3] = cmd->bo;
+	r = amdgpu_bo_list_create(test_info->device_handle, 4, resources, NULL, &bo_list);
+	CU_ASSERT_EQUAL(r, 0);
+
+	ib_info.ib_mc_address = cmd->mc_address;
+	ib_info.size = test_priv.cmd_curr;
+	ibs_request.ip_type = test_info->ip;
+	ibs_request.ring = test_info->ring;
+	ibs_request.resources = bo_list;
+	ibs_request.number_of_ibs = 1;
+	ibs_request.ibs = &ib_info;
+	ibs_request.fence_info.handle = NULL;
+	r = amdgpu_cs_submit(context_handle, 0, &ibs_request, 1);
+	CU_ASSERT_EQUAL(r, 0);
+
+	fence_status.ip_type = test_info->ip;
+	fence_status.ip_instance = 0;
+	fence_status.ring = test_info->ring;
+	fence_status.context = context_handle;
+	fence_status.fence = ibs_request.seq_no;
+
+	/* wait for IB accomplished */
+	r = amdgpu_cs_query_fence_status(&fence_status,
+					 AMDGPU_TIMEOUT_INFINITE,
+					 0, &expired);
+
+	if (!test_info->hang) {
+		CU_ASSERT_EQUAL(r, 0);
+		CU_ASSERT_EQUAL(expired, true);
+
+		/* verify if memcpy test result meets with expected */
+		i = 0;
+		ptr_dst = (uint8_t *)dst->ptr;
+		CU_ASSERT_EQUAL(memcmp(ptr_dst + i, ptr_src + i, 16), 0);
+		i = dst->size - 16;
+		CU_ASSERT_EQUAL(memcmp(ptr_dst + i, ptr_src + i, 16), 0);
+		i = dst->size / 2;
+		CU_ASSERT_EQUAL(memcmp(ptr_dst + i, ptr_src + i, 16), 0);
+	} else {
+		r = amdgpu_cs_query_reset_state(context_handle, &hang_state, &hangs);
+		CU_ASSERT_EQUAL(r, 0);
+		CU_ASSERT_EQUAL(hang_state, AMDGPU_CTX_UNKNOWN_RESET);
+	}
+
+	r = amdgpu_bo_list_destroy(bo_list);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_free(src);
+	CU_ASSERT_EQUAL(r, 0);
+	r = shader_test_bo_free(dst);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_free(shader);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_free(cmd);
+
+	r = amdgpu_cs_ctx_free(context_handle);
+	CU_ASSERT_EQUAL(r, 0);
+}
+
+static void shader_test_dispatch_cb(struct shader_test_info *test_info)
+{
+	amdgpu_test_dispatch_memset(test_info);
+	amdgpu_test_dispatch_memcpy(test_info);
+}
+static void shader_test_dispatch_hang_cb(struct shader_test_info *test_info)
+{
+	test_info->hang = 0;
+	amdgpu_test_dispatch_memcpy(test_info);
+
+	test_info->hang = 1;
+	amdgpu_test_dispatch_memcpy(test_info);
+
+	test_info->hang = 0;
+	amdgpu_test_dispatch_memcpy(test_info);
+}
+
+static void shader_test_dispatch_hang_slow_cb(struct shader_test_info *test_info)
+{
+	test_info->hang = 0;
+	test_info->hang_slow = 0;
+	amdgpu_test_dispatch_memcpy(test_info);
+
+	test_info->hang = 1;
+	test_info->hang_slow = 1;
+	amdgpu_test_dispatch_memcpy(test_info);
+
+	test_info->hang = 0;
+	test_info->hang_slow = 0;
+	amdgpu_test_dispatch_memcpy(test_info);
+}
+
+void amdgpu_test_dispatch_helper(amdgpu_device_handle device_handle, unsigned ip)
+{
+	shader_test_for_each(device_handle, ip, shader_test_dispatch_cb);
+}
+
+void amdgpu_test_dispatch_hang_helper(amdgpu_device_handle device_handle, uint32_t ip)
+{
+	shader_test_for_each(device_handle, ip, shader_test_dispatch_hang_cb);
+}
+
+void amdgpu_test_dispatch_hang_slow_helper(amdgpu_device_handle device_handle, uint32_t ip)
+{
+	shader_test_for_each(device_handle, ip, shader_test_dispatch_hang_slow_cb);
+}
+
+static void amdgpu_draw_load_ps_shader_hang_slow(struct shader_test_priv *test_priv)
+{
+	struct amdgpu_gpu_info gpu_info = {0};
+	struct shader_test_shader_bin *ps_shader_bin = &memcpy_ps_hang_slow_navi21;
+	int r;
+
+	r = amdgpu_query_gpu_info(test_priv->info->device_handle, &gpu_info);
+	CU_ASSERT_EQUAL(r, 0);
+
+	switch (gpu_info.family_id) {
+		case AMDGPU_FAMILY_AI:
+		case AMDGPU_FAMILY_RV:
+			ps_shader_bin = &memcpy_ps_hang_slow_ai;
+			break;
+		case AMDGPU_FAMILY_NV:
+			if (gpu_info.chip_external_rev < 40)
+				ps_shader_bin = &memcpy_ps_hang_slow_navi10;
+			break;
+	}
+
+	shader_test_load_shader_hang_slow(&test_priv->shader_draw.ps_bo, ps_shader_bin);
+}
+
+static uint32_t round_up_size(uint32_t size)
+{
+	return (size + 255) & ~255;
+}
+static void amdgpu_draw_load_ps_shader(struct shader_test_priv *test_priv)
+{
+	uint8_t *ptr_shader = test_priv->shader_draw.ps_bo.ptr;
+	const struct shader_test_ps_shader *shader;
+	uint32_t shader_offset, num_export_fmt;
+	uint32_t mem_offset, patch_code_offset;
+	int i;
+
+	if (test_priv->info->hang) {
+		if (test_priv->info->hang_slow)
+			amdgpu_draw_load_ps_shader_hang_slow(test_priv);
+		else
+			memcpy(ptr_shader, memcpy_shader_hang, sizeof(memcpy_shader_hang));
+
+		return;
+	}
+
+	shader = &shader_test_ps[test_priv->info->version][test_priv->shader_draw.ps_type];
+	num_export_fmt = 10;
+	shader_offset = round_up_size(shader->shader_size);
+	/* write main shader program */
+	for (i = 0 ; i < num_export_fmt; i++) {
+		mem_offset = i * shader_offset;
+		memcpy(ptr_shader + mem_offset, shader->shader, shader->shader_size);
+	}
+
+	/* overwrite patch codes */
+	for (i = 0 ; i < num_export_fmt; i++) {
+		mem_offset = i * shader_offset + shader->patchinfo_code_offset[0] * sizeof(uint32_t);
+		patch_code_offset = i * shader->patchinfo_code_size;
+		memcpy(ptr_shader + mem_offset,
+			shader->patchinfo_code + patch_code_offset,
+			shader->patchinfo_code_size * sizeof(uint32_t));
+	}
+}
+
+/* load RectPosTexFast_VS */
+static void amdgpu_draw_load_vs_shader(struct shader_test_priv *test_priv)
+{
+	uint8_t *ptr_shader = test_priv->shader_draw.vs_bo.ptr;
+	const struct shader_test_vs_shader *shader = &shader_test_vs[test_priv->info->version][test_priv->shader_draw.vs_type];
+
+	memcpy(ptr_shader, shader->shader, shader->shader_size);
+}
+
+static void amdgpu_draw_init(struct shader_test_priv *test_priv)
+{
+	int i;
+	uint32_t *ptr = test_priv->cmd.ptr;
+	const struct shader_test_gfx_info *gfx_info = &shader_test_gfx_info[test_priv->info->version];
+
+	/* Write context control and load shadowing register if necessary */
+	write_context_control(test_priv);
+	i = test_priv->cmd_curr;
+
+	if (test_priv->info->version == AMDGPU_TEST_GFX_V11) {
+		ptr[i++] = PACKET3(PACKET3_SET_UCONFIG_REG, 1);
+		ptr[i++] = 0x446;
+		ptr[i++] = (test_priv->vtx_attributes_mem.mc_address >> 16);
+		// mmSPI_ATTRIBUTE_RING_SIZE
+		ptr[i++] = PACKET3(PACKET3_SET_UCONFIG_REG, 1);
+		ptr[i++] = 0x447;
+		ptr[i++] = 0x20001;
+	}
+	memcpy(ptr + i, gfx_info->preamble_cache, gfx_info->size_preamble_cache);
+
+	test_priv->cmd_curr = i + gfx_info->size_preamble_cache/sizeof(uint32_t);
+}
+
+static void amdgpu_draw_setup_and_write_drawblt_surf_info_gfx9(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+
+	/* setup color buffer */
+	/* offset   reg
+	   0xA318   CB_COLOR0_BASE
+	   0xA319   CB_COLOR0_BASE_EXT
+	   0xA31A   CB_COLOR0_ATTRIB2
+	   0xA31B   CB_COLOR0_VIEW
+	   0xA31C   CB_COLOR0_INFO
+	   0xA31D   CB_COLOR0_ATTRIB
+	   0xA31E   CB_COLOR0_DCC_CONTROL
+	   0xA31F   CB_COLOR0_CMASK
+	   0xA320   CB_COLOR0_CMASK_BASE_EXT
+	   0xA321   CB_COLOR0_FMASK
+	   0xA322   CB_COLOR0_FMASK_BASE_EXT
+	   0xA323   CB_COLOR0_CLEAR_WORD0
+	   0xA324   CB_COLOR0_CLEAR_WORD1
+	   0xA325   CB_COLOR0_DCC_BASE
+	   0xA326   CB_COLOR0_DCC_BASE_EXT */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 15);
+	ptr[i++] = 0x318;
+	ptr[i++] = test_priv->dst.mc_address >> 8;
+	ptr[i++] = test_priv->dst.mc_address >> 40;
+	ptr[i++] = test_priv->info->hang_slow ? 0x3ffc7ff : 0x7c01f;
+	ptr[i++] = 0;
+	ptr[i++] = 0x50438;
+	ptr[i++] = 0x10140000;
+	i += 9;
+
+	/* mmCB_MRT0_EPITCH */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x1e8;
+	ptr[i++] = test_priv->info->hang_slow ? 0xfff : 0x1f;
+
+	/* 0xA32B   CB_COLOR1_BASE */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x32b;
+	ptr[i++] = 0;
+
+	/* 0xA33A   CB_COLOR1_BASE */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x33a;
+	ptr[i++] = 0;
+
+	/* SPI_SHADER_COL_FORMAT */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x1c5;
+	ptr[i++] = 9;
+
+	/* Setup depth buffer */
+	/* mmDB_Z_INFO */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 2);
+	ptr[i++] = 0xe;
+	i += 2;
+
+	test_priv->cmd_curr = i;
+}
+static void amdgpu_draw_setup_and_write_drawblt_surf_info_gfx10(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+
+	/* setup color buffer */
+	/* 0xA318   CB_COLOR0_BASE
+	   0xA319   CB_COLOR0_PITCH
+	   0xA31A   CB_COLOR0_SLICE
+	   0xA31B   CB_COLOR0_VIEW
+	   0xA31C   CB_COLOR0_INFO
+	   0xA31D   CB_COLOR0_ATTRIB
+	   0xA31E   CB_COLOR0_DCC_CONTROL
+	   0xA31F   CB_COLOR0_CMASK
+	   0xA320   CB_COLOR0_CMASK_SLICE
+	   0xA321   CB_COLOR0_FMASK
+	   0xA322   CB_COLOR0_FMASK_SLICE
+	   0xA323   CB_COLOR0_CLEAR_WORD0
+	   0xA324   CB_COLOR0_CLEAR_WORD1
+	   0xA325   CB_COLOR0_DCC_BASE */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 14);
+	ptr[i++] = 0x318;
+	ptr[i++] = test_priv->dst.mc_address >> 8;
+	i += 3;
+	ptr[i++] = 0x50438;
+	i += 9;
+
+	/* 0xA390   CB_COLOR0_BASE_EXT */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x390;
+	ptr[i++] = test_priv->dst.mc_address >> 40;
+
+	/* 0xA398   CB_COLOR0_CMASK_BASE_EXT */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x398;
+	ptr[i++] = 0;
+
+	/* 0xA3A0   CB_COLOR0_FMASK_BASE_EXT */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x3a0;
+	ptr[i++] = 0;
+
+	/* 0xA3A8   CB_COLOR0_DCC_BASE_EXT */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x3a8;
+	ptr[i++] = 0;
+
+	/* 0xA3B0   CB_COLOR0_ATTRIB2 */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x3b0;
+	ptr[i++] = test_priv->info->hang_slow ? 0x3ffc7ff : 0x7c01f;
+
+	/* 0xA3B8   CB_COLOR0_ATTRIB3 */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x3b8;
+	ptr[i++] = 0x9014000;
+
+	/* 0xA32B   CB_COLOR1_BASE */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x32b;
+	ptr[i++] = 0;
+
+	/* 0xA33A   CB_COLOR1_BASE */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x33a;
+	ptr[i++] = 0;
+
+	/* SPI_SHADER_COL_FORMAT */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x1c5;
+	ptr[i++] = 9;
+
+	/* Setup depth buffer */
+	/* mmDB_Z_INFO */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 2);
+	ptr[i++] = 0x10;
+	i += 2;
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_draw_setup_and_write_drawblt_surf_info_gfx11(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+
+	/* mmCB_COLOR0_BASE */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x318;
+	ptr[i++] = test_priv->dst.mc_address >> 8;
+	/* mmCB_COLOR0_VIEW .. mmCB_COLOR0_DCC_CONTROL */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 4);
+	ptr[i++] = 0x31b;
+	i++;
+	ptr[i++] = 0x5040e;
+	i += 2;
+	/* mmCB_COLOR0_DCC_BASE */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x325;
+	ptr[i++] = 0;
+	/* mmCB_COLOR0_BASE_EXT */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x390;
+	ptr[i++] = (test_priv->dst.mc_address >> 40) & 0xFF;
+	/* mmCB_COLOR0_DCC_BASE_EXT */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x3a8;
+	ptr[i++] = 0;
+	/* mmCB_COLOR0_ATTRIB2 */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x3b0;
+	ptr[i++] = test_priv->info->hang_slow ? 0x1ffc7ff : 0x7c01f;
+	/* mmCB_COLOR0_ATTRIB3 */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x3b8;
+	ptr[i++] = test_priv->info->hang_slow ? 0x1028000 : 0x1018000;
+	/* mmCB_COLOR0_INFO */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x32b;
+	ptr[i++] = 0;
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x33a;
+	ptr[i++] = 0;
+	/* mmSPI_SHADER_COL_FORMAT */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x1c5;
+	ptr[i++] = 0x9;
+	/* mmDB_Z_INFO */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 2);
+	ptr[i++] = 0x10;
+	i += 2;
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_draw_setup_and_write_drawblt_surf_info(struct shader_test_priv *test_priv)
+{
+	switch (test_priv->info->version) {
+	case AMDGPU_TEST_GFX_V9:
+		amdgpu_draw_setup_and_write_drawblt_surf_info_gfx9(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_V10:
+		amdgpu_draw_setup_and_write_drawblt_surf_info_gfx10(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_V11:
+		amdgpu_draw_setup_and_write_drawblt_surf_info_gfx11(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_MAX:
+		assert(1 && "Not Support gfx, never go here");
+		break;
+	}
+}
+
+static void amdgpu_draw_setup_and_write_drawblt_state_gfx9(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+	const struct shader_test_gfx_info *gfx_info = &shader_test_gfx_info[test_priv->info->version];
+
+	/* mmPA_SC_TILE_STEERING_OVERRIDE */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0xd7;
+	ptr[i++] = 0;
+
+	ptr[i++] = 0xffff1000;
+	ptr[i++] = 0xc0021000;
+
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0xd7;
+	ptr[i++] = 1;
+
+	/* mmPA_SC_AA_SAMPLE_LOCS_PIXEL_X0Y0_0 */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 16);
+	ptr[i++] = 0x2fe;
+	i += 16;
+
+	/* mmPA_SC_CENTROID_PRIORITY_0 */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 2);
+	ptr[i++] = 0x2f5;
+	i += 2;
+
+	memcpy(ptr + i, gfx_info->cached_cmd, gfx_info->size_cached_cmd);
+	if (test_priv->info->hang_slow)
+		*(ptr + i + 12) = 0x8000800;
+
+	test_priv->cmd_curr = i + gfx_info->size_cached_cmd/sizeof(uint32_t);
+}
+
+static void amdgpu_draw_setup_and_write_drawblt_state_gfx10(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+	const struct shader_test_gfx_info *gfx_info = &shader_test_gfx_info[test_priv->info->version];
+
+	/* mmPA_SC_TILE_STEERING_OVERRIDE */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0xd7;
+	ptr[i++] = 0;
+
+	ptr[i++] = 0xffff1000;
+	ptr[i++] = 0xc0021000;
+
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0xd7;
+	ptr[i++] = 0;
+
+	/* mmPA_SC_AA_SAMPLE_LOCS_PIXEL_X0Y0_0 */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 16);
+	ptr[i++] = 0x2fe;
+	i += 16;
+
+	/* mmPA_SC_CENTROID_PRIORITY_0 */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 2);
+	ptr[i++] = 0x2f5;
+	i += 2;
+
+	memcpy(ptr + i, gfx_info->cached_cmd, gfx_info->size_cached_cmd);
+	if (test_priv->info->hang_slow)
+		*(ptr + i + 12) = 0x8000800;
+	i += gfx_info->size_cached_cmd/sizeof(uint32_t);
+
+	/* mmCB_RMI_GL2_CACHE_CONTROL */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x104;
+	ptr[i++] = 0x40aa0055;
+	/* mmDB_RMI_L2_CACHE_CONTROL */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x1f;
+	ptr[i++] = 0x2a0055;
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_draw_setup_and_write_drawblt_state_gfx11(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+	const struct shader_test_gfx_info *gfx_info = &shader_test_gfx_info[test_priv->info->version];
+
+	/* mmPA_SC_TILE_STEERING_OVERRIDE */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0xd7;
+	ptr[i++] = 0;
+
+	ptr[i++] = 0xffff1000;
+	ptr[i++] = 0xc0021000;
+
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0xd7;
+	i++;
+
+	/* mmPA_SC_AA_SAMPLE_LOCS_PIXEL_X0Y0_0 */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 16);
+	ptr[i++] = 0x2fe;
+	i += 16;
+
+	/* mmPA_SC_CENTROID_PRIORITY_0 */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 2);
+	ptr[i++] = 0x2f5;
+	i += 2;
+
+	memcpy(ptr + i, gfx_info->cached_cmd, gfx_info->size_cached_cmd);
+	if (test_priv->info->hang_slow)
+		*(ptr + i + 12) = 0x8000800;
+
+	test_priv->cmd_curr = i + gfx_info->size_cached_cmd/sizeof(uint32_t);
+}
+
+static void amdgpu_draw_setup_and_write_drawblt_state(struct shader_test_priv *test_priv)
+{
+	switch (test_priv->info->version) {
+	case AMDGPU_TEST_GFX_V9:
+		amdgpu_draw_setup_and_write_drawblt_state_gfx9(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_V10:
+		amdgpu_draw_setup_and_write_drawblt_state_gfx10(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_V11:
+		amdgpu_draw_setup_and_write_drawblt_state_gfx11(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_MAX:
+		assert(1 && "Not Support gfx, never go here");
+		break;
+	}
+}
+
+static void amdgpu_draw_vs_RectPosTexFast_write2hw_gfx9(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+	uint64_t shader_addr = test_priv->shader_draw.vs_bo.mc_address;
+	enum ps_type ps = test_priv->shader_draw.ps_type;
+
+	/* mmPA_CL_VS_OUT_CNTL */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x207;
+	ptr[i++] = 0;
+
+	/* mmSPI_SHADER_PGM_RSRC3_VS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 1);
+	ptr[i++] = 0x46;
+	ptr[i++] = 0xffff;
+
+	/* mmSPI_SHADER_PGM_LO_VS...mmSPI_SHADER_PGM_HI_VS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 2);
+	ptr[i++] = 0x48;
+	ptr[i++] = shader_addr >> 8;
+	ptr[i++] = shader_addr >> 40;
+
+	/* mmSPI_SHADER_PGM_RSRC1_VS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 1);
+	ptr[i++] = 0x4a;
+	ptr[i++] = 0xc0081;
+
+	/* mmSPI_SHADER_PGM_RSRC2_VS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 1);
+	ptr[i++] = 0x4b;
+	ptr[i++] = 0x18;
+
+	/* mmSPI_VS_OUT_CONFIG */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x1b1;
+	ptr[i++] = 2;
+
+	/* mmSPI_SHADER_POS_FORMAT */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x1c3;
+	ptr[i++] = 4;
+
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 4);
+	ptr[i++] = 0x4c;
+	i += 2;
+	ptr[i++] = test_priv->info->hang_slow ? 0x45000000 : 0x42000000;
+	ptr[i++] = test_priv->info->hang_slow ? 0x45000000 : 0x42000000;
+
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 4);
+	ptr[i++] = 0x50;
+	i += 2;
+	if (ps == PS_CONST) {
+		i += 2;
+	} else if (ps == PS_TEX) {
+		ptr[i++] = 0x3f800000;
+		ptr[i++] = 0x3f800000;
+	}
+
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 4);
+	ptr[i++] = 0x54;
+	i += 4;
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_draw_vs_RectPosTexFast_write2hw_gfx10(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+	uint64_t shader_addr = test_priv->shader_draw.vs_bo.mc_address;
+	enum ps_type ps = test_priv->shader_draw.ps_type;
+
+	/* mmPA_CL_VS_OUT_CNTL */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x207;
+	ptr[i++] = 0;
+
+	/* mmSPI_SHADER_PGM_RSRC3_VS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG_INDEX, 1);
+	ptr[i++] = 0x30000046;
+	ptr[i++] = 0xffff;
+	/* mmSPI_SHADER_PGM_RSRC4_VS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG_INDEX, 1);
+	ptr[i++] = 0x30000041;
+	ptr[i++] = 0xffff;
+
+	/* mmSPI_SHADER_PGM_LO_VS...mmSPI_SHADER_PGM_HI_VS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 2);
+	ptr[i++] = 0x48;
+	ptr[i++] = shader_addr >> 8;
+	ptr[i++] = shader_addr >> 40;
+
+	/* mmSPI_SHADER_PGM_RSRC1_VS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 1);
+	ptr[i++] = 0x4a;
+	ptr[i++] = 0xc0041;
+	/* mmSPI_SHADER_PGM_RSRC2_VS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 1);
+	ptr[i++] = 0x4b;
+	ptr[i++] = 0x18;
+
+	/* mmSPI_VS_OUT_CONFIG */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x1b1;
+	ptr[i++] = 2;
+
+	/* mmSPI_SHADER_POS_FORMAT */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x1c3;
+	ptr[i++] = 4;
+
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 4);
+	ptr[i++] = 0x4c;
+	i += 2;
+	ptr[i++] = test_priv->info->hang_slow ? 0x45000000 : 0x42000000;
+	ptr[i++] = test_priv->info->hang_slow ? 0x45000000 : 0x42000000;
+
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 4);
+	ptr[i++] = 0x50;
+	i += 2;
+	if (ps == PS_CONST) {
+		i += 2;
+	} else if (ps == PS_TEX) {
+		ptr[i++] = 0x3f800000;
+		ptr[i++] = 0x3f800000;
+	}
+
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 4);
+	ptr[i++] = 0x54;
+	i += 4;
+
+	test_priv->cmd_curr = i;
+}
+
+
+static void amdgpu_draw_vs_RectPosTexFast_write2hw_gfx11(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+	const struct shader_test_gfx_info *gfx_info = &shader_test_gfx_info[test_priv->info->version];
+	uint64_t shader_addr = test_priv->shader_draw.vs_bo.mc_address;
+	const struct shader_test_vs_shader *shader = &shader_test_vs[test_priv->info->version][test_priv->shader_draw.vs_type];
+	enum ps_type ps = test_priv->shader_draw.ps_type;
+	int j, offset;
+
+	/* mmPA_CL_VS_OUT_CNTL */
+	ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr[i++] = 0x207;
+	ptr[i++] = 0;
+
+	/* mmSPI_SHADER_PGM_RSRC3_GS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG_INDEX, 1);
+	ptr[i++] = 0x30000087;
+	ptr[i++] = 0xffff;
+	/* mmSPI_SHADER_PGM_RSRC4_GS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG_INDEX, 1);
+	ptr[i++] = 0x30000081;
+	ptr[i++] = 0x1fff0001;
+
+	/* mmSPI_SHADER_PGM_LO_ES */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 2);
+	ptr[i++] = 0xc8;
+	ptr[i++] = shader_addr >> 8;
+	ptr[i++] = shader_addr >> 40;
+
+	/* write sh reg */
+	for (j = 0; j < shader->num_sh_reg; j++) {
+		ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 1);
+		ptr[i++] = shader->sh_reg[j].reg_offset - gfx_info->sh_reg_base;
+		ptr[i++] = shader->sh_reg[j].reg_value;
+	}
+	/* write context reg */
+	for (j = 0; j < shader->num_context_reg; j++) {
+		switch (shader->context_reg[j].reg_offset) {
+		case 0xA1B1: //mmSPI_VS_OUT_CONFIG
+			ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+			ptr[i++] = shader->context_reg[j].reg_offset - gfx_info->context_reg_base;
+			ptr[i++] = 2;
+			break;
+		case 0xA1C3: //mmSPI_SHADER_POS_FORMAT
+			ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+			ptr[i++] = shader->context_reg[j].reg_offset - gfx_info->context_reg_base;
+			ptr[i++] = 4;
+			break;
+		case 0xA2E4: //mmVGT_GS_INSTANCE_CNT
+		case 0xA2CE: //mmVGT_GS_MAX_VERT_OUT
+			break;
+		default:
+			ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+			ptr[i++] = shader->context_reg[j].reg_offset - gfx_info->context_reg_base;
+			ptr[i++] = shader->context_reg[j].reg_value;
+			break;
+		}
+	}
+
+	// write constant
+	// dst rect
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 4);
+	ptr[i++] = 0x8c;
+	i += 2;
+	ptr[i++] = test_priv->info->hang_slow ? 0x45000000 : 0x42000000;
+	ptr[i++] = test_priv->info->hang_slow ? 0x45000000 : 0x42000000;
+	// src rect
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 4);
+	ptr[i++] = 0x90;
+	i += 2;
+	if (ps == PS_CONST) {
+		i += 2;
+	} else if (ps == PS_TEX) {
+		ptr[i++] = 0x3f800000;
+		ptr[i++] = 0x3f800000;
+	}
+
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 4);
+	ptr[i++] = 0x94;
+	i += 4;
+	// vtx_attributes_mem
+	ptr[i++] = 0xc02f1000;
+	offset = i * sizeof(uint32_t);
+	i += 44;
+	ptr[i++] = test_priv->vtx_attributes_mem.mc_address & 0xffffffff;
+	ptr[i++] = 0xc0100000 | ((test_priv->vtx_attributes_mem.mc_address >> 32) & 0xffff);
+	ptr[i++] = test_priv->vtx_attributes_mem.size / 16;
+	ptr[i++] = 0x2043ffac;
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG_OFFSET, 2);
+	ptr[i++] = 0x98;
+	ptr[i++] = offset;
+	i++;
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_draw_vs_RectPosTexFast_write2hw(struct shader_test_priv *test_priv)
+{
+	switch (test_priv->info->version) {
+	case AMDGPU_TEST_GFX_V9:
+		amdgpu_draw_vs_RectPosTexFast_write2hw_gfx9(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_V10:
+		amdgpu_draw_vs_RectPosTexFast_write2hw_gfx10(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_V11:
+		amdgpu_draw_vs_RectPosTexFast_write2hw_gfx11(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_MAX:
+		assert(1 && "Not Support gfx, never go here");
+		break;
+	}
+}
+
+static void amdgpu_draw_ps_write2hw_gfx9_10(struct shader_test_priv *test_priv)
+{
+	int i, j;
+	uint64_t shader_addr = test_priv->shader_draw.ps_bo.mc_address;
+	const struct shader_test_ps_shader *ps = &shader_test_ps[test_priv->info->version][test_priv->shader_draw.ps_type];
+	uint32_t *ptr = test_priv->cmd.ptr;
+
+	i = test_priv->cmd_curr;
+
+	if (test_priv->info->version == AMDGPU_TEST_GFX_V9) {
+		/* 0x2c07   SPI_SHADER_PGM_RSRC3_PS
+		   0x2c08   SPI_SHADER_PGM_LO_PS
+		   0x2c09   SPI_SHADER_PGM_HI_PS */
+		/* multiplicator 9 is from  SPI_SHADER_COL_FORMAT */
+		if (!test_priv->info->hang)
+			shader_addr += 256 * 9;
+		ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 3);
+		ptr[i++] = 0x7;
+		ptr[i++] = 0xffff;
+		ptr[i++] = shader_addr >> 8;
+		ptr[i++] = shader_addr >> 40;
+	} else {
+		//if (!test_priv->info->hang)
+			shader_addr += 256 * 9;
+		/* 0x2c08	 SPI_SHADER_PGM_LO_PS
+		     0x2c09	 SPI_SHADER_PGM_HI_PS */
+		ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 2);
+		ptr[i++] = 0x8;
+		ptr[i++] = shader_addr >> 8;
+		ptr[i++] = shader_addr >> 40;
+
+		/* mmSPI_SHADER_PGM_RSRC3_PS */
+		ptr[i++] = PACKET3(PACKET3_SET_SH_REG_INDEX, 1);
+		ptr[i++] = 0x30000007;
+		ptr[i++] = 0xffff;
+		/* mmSPI_SHADER_PGM_RSRC4_PS */
+		ptr[i++] = PACKET3(PACKET3_SET_SH_REG_INDEX, 1);
+		ptr[i++] = 0x30000001;
+		ptr[i++] = 0xffff;
+	}
+
+	for (j = 0; j < ps->num_sh_reg; j++) {
+		ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 1);
+		ptr[i++] = ps->sh_reg[j].reg_offset - 0x2c00;
+		ptr[i++] = ps->sh_reg[j].reg_value;
+	}
+
+	for (j = 0; j < ps->num_context_reg; j++) {
+		if (ps->context_reg[j].reg_offset != 0xA1C5) {
+			ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+			ptr[i++] = ps->context_reg[j].reg_offset - 0xa000;
+			ptr[i++] = ps->context_reg[j].reg_value;
+		}
+
+		if (ps->context_reg[j].reg_offset == 0xA1B4) {
+			ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+			ptr[i++] = 0x1b3;
+			ptr[i++] = 2;
+		}
+	}
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_draw_ps_write2hw_gfx11(struct shader_test_priv *test_priv)
+{
+	int i, j;
+	uint64_t shader_addr = test_priv->shader_draw.ps_bo.mc_address;
+	enum amdgpu_test_gfx_version version = test_priv->info->version;
+	const struct shader_test_ps_shader *ps = &shader_test_ps[version][test_priv->shader_draw.ps_type];
+	uint32_t *ptr = test_priv->cmd.ptr;
+	uint32_t export_shader_offset;
+
+	i = test_priv->cmd_curr;
+
+	/* SPI_SHADER_PGM_LO_PS
+	   SPI_SHADER_PGM_HI_PS */
+	shader_addr >>= 8;
+	if (!test_priv->info->hang) {
+		export_shader_offset = (round_up_size(ps->shader_size) * 9) >> 8;
+		shader_addr += export_shader_offset;
+	}
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 2);
+	ptr[i++] = 0x8;
+	ptr[i++] = shader_addr & 0xffffffff;
+	ptr[i++] = (shader_addr >> 32) & 0xffffffff;
+	/* mmSPI_SHADER_PGM_RSRC3_PS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG_INDEX, 1);
+	ptr[i++] = 0x30000007;
+	ptr[i++] = 0xffff;
+	/* mmSPI_SHADER_PGM_RSRC4_PS */
+	ptr[i++] = PACKET3(PACKET3_SET_SH_REG_INDEX, 1);
+	ptr[i++] = 0x30000001;
+	ptr[i++] = 0x3fffff;
+
+	for (j = 0; j < ps->num_sh_reg; j++) {
+		ptr[i++] = PACKET3(PACKET3_SET_SH_REG, 1);
+		ptr[i++] = ps->sh_reg[j].reg_offset - shader_test_gfx_info[version].sh_reg_base;
+		ptr[i++] = ps->sh_reg[j].reg_value;
+	}
+
+	for (j = 0; j < ps->num_context_reg; j++) {
+		/* !mmSPI_SHADER_COL_FORMAT */
+		if (ps->context_reg[j].reg_offset != 0xA1C5) {
+			ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+			ptr[i++] = ps->context_reg[j].reg_offset - shader_test_gfx_info[version].context_reg_base;
+			ptr[i++] = ps->context_reg[j].reg_value;
+		}
+
+		/* mmSPI_PS_INPUT_ADDR */
+		if (ps->context_reg[j].reg_offset == 0xA1B4) {
+			ptr[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+			ptr[i++] = 0x1b3;
+			ptr[i++] = 2;
+		}
+	}
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_draw_ps_write2hw(struct shader_test_priv *test_priv)
+{
+	switch (test_priv->info->version) {
+	case AMDGPU_TEST_GFX_V9:
+	case AMDGPU_TEST_GFX_V10:
+		amdgpu_draw_ps_write2hw_gfx9_10(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_V11:
+		amdgpu_draw_ps_write2hw_gfx11(test_priv);
+		break;
+	case AMDGPU_TEST_GFX_MAX:
+		assert(1 && "Not Support gfx, never go here");
+		break;
+	}
+}
+
+static void amdgpu_draw_draw(struct shader_test_priv *test_priv)
+{
+	int i = test_priv->cmd_curr;
+	uint32_t *ptr = test_priv->cmd.ptr;
+
+	switch (test_priv->info->version) {
+	case AMDGPU_TEST_GFX_V9:
+		/* mmIA_MULTI_VGT_PARAM */
+		ptr[i++] = PACKET3(PACKET3_SET_UCONFIG_REG, 1);
+		ptr[i++] = 0x40000258;
+		ptr[i++] = 0xd00ff;
+		/* mmVGT_PRIMITIVE_TYPE */
+		ptr[i++] = PACKET3(PACKET3_SET_UCONFIG_REG, 1);
+		ptr[i++] = 0x10000242;
+		ptr[i++] = 0x11;
+		break;
+	case AMDGPU_TEST_GFX_V10:
+		/* mmGE_CNTL */
+		ptr[i++] = PACKET3(PACKET3_SET_UCONFIG_REG, 1);
+		ptr[i++] = 0x25b;
+		ptr[i++] = 0xff;
+		/* mmVGT_PRIMITIVE_TYPE */
+		ptr[i++] = PACKET3(PACKET3_SET_UCONFIG_REG, 1);
+		ptr[i++] = 0x242;
+		ptr[i++] = 0x11;
+		break;
+	case AMDGPU_TEST_GFX_V11:
+		/* mmGE_CNTL */
+		ptr[i++] = PACKET3(PACKET3_SET_UCONFIG_REG, 1);
+		ptr[i++] = 0x25b;
+		ptr[i++] = 0x80fc80;
+		/* mmVGT_PRIMITIVE_TYPE */
+		ptr[i++] = PACKET3(PACKET3_SET_UCONFIG_REG, 1);
+		ptr[i++] = 0x242;
+		ptr[i++] = 0x11;
+		break;
+	case AMDGPU_TEST_GFX_MAX:
+		assert(1 && "Not Support gfx, never go here");
+		break;
+	}
+
+	ptr[i++] = PACKET3(PACKET3_DRAW_INDEX_AUTO, 1);
+	ptr[i++] = 3;
+	ptr[i++] = 2;
+
+	test_priv->cmd_curr = i;
+}
+
+static void amdgpu_memset_draw_test(struct shader_test_info *test_info)
+{
+	struct shader_test_priv test_priv;
+	amdgpu_context_handle context_handle;
+	struct shader_test_bo *ps_bo = &(test_priv.shader_draw.ps_bo);
+	struct shader_test_bo *vs_bo = &(test_priv.shader_draw.vs_bo);
+	struct shader_test_bo *dst = &(test_priv.dst);
+	struct shader_test_bo *cmd = &(test_priv.cmd);
+	struct shader_test_bo *vtx_attributes_mem = &(test_priv.vtx_attributes_mem);
+	amdgpu_bo_handle resources[5];
+	uint8_t *ptr_dst;
+	uint32_t *ptr_cmd;
+	int i, r;
+	struct amdgpu_cs_request ibs_request = {0};
+	struct amdgpu_cs_ib_info ib_info = {0};
+	struct amdgpu_cs_fence fence_status = {0};
+	uint32_t expired;
+	amdgpu_bo_list_handle bo_list;
+	uint8_t cptr[16];
+
+	memset(&test_priv, 0, sizeof(test_priv));
+	test_priv.info = test_info;
+
+	r = amdgpu_cs_ctx_create(test_info->device_handle, &context_handle);
+	CU_ASSERT_EQUAL(r, 0);
+
+	ps_bo->size = 0x2000;
+	ps_bo->heap = AMDGPU_GEM_DOMAIN_VRAM;
+	r = shader_test_bo_alloc(test_info->device_handle, ps_bo);
+	CU_ASSERT_EQUAL(r, 0);
+	memset(ps_bo->ptr, 0, ps_bo->size);
+
+	vs_bo->size = 4096;
+	vs_bo->heap = AMDGPU_GEM_DOMAIN_VRAM;
+	r = shader_test_bo_alloc(test_info->device_handle, vs_bo);
+	CU_ASSERT_EQUAL(r, 0);
+	memset(vs_bo->ptr, 0, vs_bo->size);
+
+	test_priv.shader_draw.ps_type = PS_CONST;
+	amdgpu_draw_load_ps_shader(&test_priv);
+
+	test_priv.shader_draw.vs_type = VS_RECTPOSTEXFAST;
+	amdgpu_draw_load_vs_shader(&test_priv);
+
+	cmd->size = 4096;
+	cmd->heap = AMDGPU_GEM_DOMAIN_GTT;
+	r = shader_test_bo_alloc(test_info->device_handle, cmd);
+	CU_ASSERT_EQUAL(r, 0);
+	ptr_cmd = cmd->ptr;
+	memset(ptr_cmd, 0, cmd->size);
+
+	dst->size = 0x4000;
+	dst->heap = AMDGPU_GEM_DOMAIN_VRAM;
+	r = shader_test_bo_alloc(test_info->device_handle, dst);
+	CU_ASSERT_EQUAL(r, 0);
+
+	if (test_info->version == AMDGPU_TEST_GFX_V11) {
+		vtx_attributes_mem->size = 0x4040000;
+		vtx_attributes_mem->heap = AMDGPU_GEM_DOMAIN_VRAM;
+
+		r = shader_test_bo_alloc(test_info->device_handle, vtx_attributes_mem);
+		CU_ASSERT_EQUAL(r, 0);
+	}
+
+	amdgpu_draw_init(&test_priv);
+
+	amdgpu_draw_setup_and_write_drawblt_surf_info(&test_priv);
+
+	amdgpu_draw_setup_and_write_drawblt_state(&test_priv);
+
+	amdgpu_draw_vs_RectPosTexFast_write2hw(&test_priv);
+
+	amdgpu_draw_ps_write2hw(&test_priv);
+
+	i = test_priv.cmd_curr;
+	/* ps constant data */
+	ptr_cmd[i++] = PACKET3(PACKET3_SET_SH_REG, 4);
+	ptr_cmd[i++] = 0xc;
+	ptr_cmd[i++] = 0x33333333;
+	ptr_cmd[i++] = 0x33333333;
+	ptr_cmd[i++] = 0x33333333;
+	ptr_cmd[i++] = 0x33333333;
+	test_priv.cmd_curr = i;
+
+	amdgpu_draw_draw(&test_priv);
+
+	i = test_priv.cmd_curr;
+	while (i & 7)
+		ptr_cmd[i++] = 0xffff1000; /* type3 nop packet */
+	test_priv.cmd_curr = i;
+
+	i = 0;
+	resources[i++] = dst->bo;
+	resources[i++] = ps_bo->bo;
+	resources[i++] = vs_bo->bo;
+	resources[i++] = cmd->bo;
+	if (vtx_attributes_mem->size)
+		resources[i++] = vtx_attributes_mem->bo;
+	r = amdgpu_bo_list_create(test_info->device_handle, i, resources, NULL, &bo_list);
+	CU_ASSERT_EQUAL(r, 0);
+
+	ib_info.ib_mc_address = cmd->mc_address;
+	ib_info.size = test_priv.cmd_curr;
+	ibs_request.ip_type = test_info->ip;
+	ibs_request.ring = test_info->ring;
+	ibs_request.resources = bo_list;
+	ibs_request.number_of_ibs = 1;
+	ibs_request.ibs = &ib_info;
+	ibs_request.fence_info.handle = NULL;
+
+	/* submit CS */
+	r = amdgpu_cs_submit(context_handle, 0, &ibs_request, 1);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = amdgpu_bo_list_destroy(bo_list);
+	CU_ASSERT_EQUAL(r, 0);
+
+	fence_status.ip_type = test_info->ip;
+	fence_status.ip_instance = 0;
+	fence_status.ring = test_info->ring;
+	fence_status.context = context_handle;
+	fence_status.fence = ibs_request.seq_no;
+
+	/* wait for IB accomplished */
+	r = amdgpu_cs_query_fence_status(&fence_status,
+					 AMDGPU_TIMEOUT_INFINITE,
+					 0, &expired);
+	CU_ASSERT_EQUAL(r, 0);
+	CU_ASSERT_EQUAL(expired, true);
+
+	/* verify if memset test result meets with expected */
+	i = 0;
+	ptr_dst = dst->ptr;
+	memset(cptr, 0x33, 16);
+	CU_ASSERT_EQUAL(memcmp(ptr_dst + i, cptr, 16), 0);
+	i = dst->size - 16;
+	CU_ASSERT_EQUAL(memcmp(ptr_dst + i, cptr, 16), 0);
+	i = dst->size / 2;
+	CU_ASSERT_EQUAL(memcmp(ptr_dst + i, cptr, 16), 0);
+
+	if (vtx_attributes_mem->size) {
+		r = shader_test_bo_free(vtx_attributes_mem);
+		CU_ASSERT_EQUAL(r, 0);
+	}
+
+	r = shader_test_bo_free(dst);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_free(cmd);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_free(ps_bo);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_free(vs_bo);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = amdgpu_cs_ctx_free(context_handle);
+	CU_ASSERT_EQUAL(r, 0);
+}
+
+static void amdgpu_memcpy_draw_test(struct shader_test_info *test_info)
+{
+	struct shader_test_priv test_priv;
+	amdgpu_context_handle context_handle;
+	struct shader_test_bo *ps_bo = &(test_priv.shader_draw.ps_bo);
+	struct shader_test_bo *vs_bo = &(test_priv.shader_draw.vs_bo);
+	struct shader_test_bo *src = &(test_priv.src);
+	struct shader_test_bo *dst = &(test_priv.dst);
+	struct shader_test_bo *cmd = &(test_priv.cmd);
+	struct shader_test_bo *vtx_attributes_mem = &(test_priv.vtx_attributes_mem);
+	amdgpu_bo_handle resources[6];
+	uint8_t *ptr_dst;
+	uint8_t *ptr_src;
+	uint32_t *ptr_cmd;
+	int i, r;
+	struct amdgpu_cs_request ibs_request = {0};
+	struct amdgpu_cs_ib_info ib_info = {0};
+	uint32_t hang_state, hangs;
+	uint32_t expired;
+	amdgpu_bo_list_handle bo_list;
+	struct amdgpu_cs_fence fence_status = {0};
+
+	memset(&test_priv, 0, sizeof(test_priv));
+	test_priv.info = test_info;
+	test_priv.cmd.size = 4096;
+	test_priv.cmd.heap = AMDGPU_GEM_DOMAIN_GTT;
+
+	ps_bo->heap = AMDGPU_GEM_DOMAIN_VRAM;
+	test_priv.shader_draw.ps_type = PS_TEX;
+	vs_bo->size = 4096;
+	vs_bo->heap = AMDGPU_GEM_DOMAIN_VRAM;
+	test_priv.shader_draw.vs_type = VS_RECTPOSTEXFAST;
+	test_priv.src.heap = AMDGPU_GEM_DOMAIN_VRAM;
+	test_priv.dst.heap = AMDGPU_GEM_DOMAIN_VRAM;
+	if (test_info->hang_slow) {
+		test_priv.shader_draw.ps_bo.size = 16*1024*1024;
+		test_priv.src.size = 0x4000000;
+		test_priv.dst.size = 0x4000000;
+	} else {
+		test_priv.shader_draw.ps_bo.size = 0x2000;
+		test_priv.src.size = 0x4000;
+		test_priv.dst.size = 0x4000;
+	}
+
+	r = amdgpu_cs_ctx_create(test_info->device_handle, &context_handle);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_alloc(test_info->device_handle, ps_bo);
+	CU_ASSERT_EQUAL(r, 0);
+	memset(ps_bo->ptr, 0, ps_bo->size);
+
+	r = shader_test_bo_alloc(test_info->device_handle, vs_bo);
+	CU_ASSERT_EQUAL(r, 0);
+	memset(vs_bo->ptr, 0, vs_bo->size);
+
+	amdgpu_draw_load_ps_shader(&test_priv);
+	amdgpu_draw_load_vs_shader(&test_priv);
+
+	r = shader_test_bo_alloc(test_info->device_handle, cmd);
+	CU_ASSERT_EQUAL(r, 0);
+	ptr_cmd = cmd->ptr;
+	memset(ptr_cmd, 0, cmd->size);
+
+	r = shader_test_bo_alloc(test_info->device_handle, src);
+	CU_ASSERT_EQUAL(r, 0);
+	ptr_src = src->ptr;
+	memset(ptr_src, 0x55, src->size);
+
+	r = shader_test_bo_alloc(test_info->device_handle, dst);
+	CU_ASSERT_EQUAL(r, 0);
+
+	if (test_info->version == AMDGPU_TEST_GFX_V11) {
+		vtx_attributes_mem->size = 0x4040000;
+		vtx_attributes_mem->heap = AMDGPU_GEM_DOMAIN_VRAM;
+
+		r = shader_test_bo_alloc(test_info->device_handle, vtx_attributes_mem);
+		CU_ASSERT_EQUAL(r, 0);
+	}
+
+	amdgpu_draw_init(&test_priv);
+
+	amdgpu_draw_setup_and_write_drawblt_surf_info(&test_priv);
+
+	amdgpu_draw_setup_and_write_drawblt_state(&test_priv);
+
+	amdgpu_draw_vs_RectPosTexFast_write2hw(&test_priv);
+
+	amdgpu_draw_ps_write2hw(&test_priv);
+
+	// write ps user constant data
+	i = test_priv.cmd_curr;
+	ptr_cmd[i++] = PACKET3(PACKET3_SET_SH_REG, 8);
+	switch (test_info->version) {
+	case AMDGPU_TEST_GFX_V9:
+		ptr_cmd[i++] = 0xc;
+		ptr_cmd[i++] = src->mc_address >> 8;
+		ptr_cmd[i++] = src->mc_address >> 40 | 0x10e00000;
+		ptr_cmd[i++] = test_info->hang_slow ? 0x1ffcfff : 0x7c01f;
+		ptr_cmd[i++] = 0x90500fac;
+		ptr_cmd[i++] = test_info->hang_slow ? 0x1ffe000 : 0x3e000;
+		i += 3;
+		break;
+	case AMDGPU_TEST_GFX_V10:
+		ptr_cmd[i++] = 0xc;
+		ptr_cmd[i++] = src->mc_address >> 8;
+		ptr_cmd[i++] = src->mc_address >> 40 | 0xc4b00000;
+		ptr_cmd[i++] = test_info->hang_slow ? 0x81ffc1ff : 0x8007c007;
+		ptr_cmd[i++] = 0x90500fac;
+		i += 2;
+		ptr_cmd[i++] = test_info->hang_slow ? 0 : 0x400;
+		i++;
+		break;
+	case AMDGPU_TEST_GFX_V11:
+		ptr_cmd[i++] = 0xc;
+		ptr_cmd[i++] = src->mc_address >> 8;
+		ptr_cmd[i++] = src->mc_address >> 40 | 0xc4b00000;
+		ptr_cmd[i++] = test_info->hang_slow ? 0x1ffc1ff : 0x7c007;
+		ptr_cmd[i++] = test_info->hang_slow ? 0x90a00fac : 0x90600fac;
+		i += 2;
+		ptr_cmd[i++] = 0x400;
+		i++;
+		break;
+	case AMDGPU_TEST_GFX_MAX:
+		assert(1 && "Not Support gfx, never go here");
+		break;
+	}
+
+	ptr_cmd[i++] = PACKET3(PACKET3_SET_SH_REG, 4);
+	ptr_cmd[i++] = 0x14;
+	ptr_cmd[i++] = 0x92;
+	i += 3;
+
+	ptr_cmd[i++] = PACKET3(PACKET3_SET_CONTEXT_REG, 1);
+	ptr_cmd[i++] = 0x191;
+	ptr_cmd[i++] = 0;
+	test_priv.cmd_curr = i;
+
+	amdgpu_draw_draw(&test_priv);
+
+	i = test_priv.cmd_curr;
+	while (i & 7)
+		ptr_cmd[i++] = 0xffff1000; /* type3 nop packet */
+	test_priv.cmd_curr = i;
+
+	i = 0;
+	resources[i++] = dst->bo;
+	resources[i++] = src->bo;
+	resources[i++] = ps_bo->bo;
+	resources[i++] = vs_bo->bo;
+	resources[i++] = cmd->bo;
+	if (vtx_attributes_mem->size)
+		resources[i++] = vtx_attributes_mem->bo;
+	r = amdgpu_bo_list_create(test_info->device_handle, i, resources, NULL, &bo_list);
+	CU_ASSERT_EQUAL(r, 0);
+
+	ib_info.ib_mc_address = cmd->mc_address;
+	ib_info.size = test_priv.cmd_curr;
+	ibs_request.ip_type = test_info->ip;
+	ibs_request.ring = test_info->ring;
+	ibs_request.resources = bo_list;
+	ibs_request.number_of_ibs = 1;
+	ibs_request.ibs = &ib_info;
+	ibs_request.fence_info.handle = NULL;
+	r = amdgpu_cs_submit(context_handle, 0, &ibs_request, 1);
+	CU_ASSERT_EQUAL(r, 0);
+
+	fence_status.ip_type = test_info->ip;
+	fence_status.ip_instance = 0;
+	fence_status.ring = test_info->ring;
+	fence_status.context = context_handle;
+	fence_status.fence = ibs_request.seq_no;
+
+	/* wait for IB accomplished */
+	r = amdgpu_cs_query_fence_status(&fence_status,
+					 AMDGPU_TIMEOUT_INFINITE,
+					 0, &expired);
+	if (!test_info->hang) {
+		CU_ASSERT_EQUAL(r, 0);
+		CU_ASSERT_EQUAL(expired, true);
+
+		/* verify if memcpy test result meets with expected */
+		i = 0;
+		ptr_dst = dst->ptr;
+		CU_ASSERT_EQUAL(memcmp(ptr_dst + i, ptr_src + i, 16), 0);
+		i = dst->size - 16;
+		CU_ASSERT_EQUAL(memcmp(ptr_dst + i, ptr_src + i, 16), 0);
+		i = dst->size / 2;
+		CU_ASSERT_EQUAL(memcmp(ptr_dst + i, ptr_src + i, 16), 0);
+	} else {
+		r = amdgpu_cs_query_reset_state(context_handle, &hang_state, &hangs);
+		CU_ASSERT_EQUAL(r, 0);
+		CU_ASSERT_EQUAL(hang_state, AMDGPU_CTX_UNKNOWN_RESET);
+	}
+
+	r = amdgpu_bo_list_destroy(bo_list);
+	CU_ASSERT_EQUAL(r, 0);
+
+	if (vtx_attributes_mem->size) {
+		r = shader_test_bo_free(vtx_attributes_mem);
+		CU_ASSERT_EQUAL(r, 0);
+	}
+
+	r = shader_test_bo_free(src);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_free(dst);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_free(cmd);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_free(ps_bo);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = shader_test_bo_free(vs_bo);
+	CU_ASSERT_EQUAL(r, 0);
+
+	r = amdgpu_cs_ctx_free(context_handle);
+	CU_ASSERT_EQUAL(r, 0);
+}
+
+static void shader_test_draw_cb(struct shader_test_info *test_info)
+{
+	amdgpu_memset_draw_test(test_info);
+	amdgpu_memcpy_draw_test(test_info);
+}
+
+static void shader_test_draw_hang_cb(struct shader_test_info *test_info)
+{
+	test_info->hang = 0;
+	amdgpu_memcpy_draw_test(test_info);
+
+	test_info->hang = 1;
+	amdgpu_memcpy_draw_test(test_info);
+
+	test_info->hang = 0;
+	amdgpu_memcpy_draw_test(test_info);
+}
+
+static void shader_test_draw_hang_slow_cb(struct shader_test_info *test_info)
+{
+	test_info->hang = 0;
+	test_info->hang_slow = 0;
+	amdgpu_memcpy_draw_test(test_info);
+
+	test_info->hang = 1;
+	test_info->hang_slow = 1;
+	amdgpu_memcpy_draw_test(test_info);
+
+	test_info->hang = 0;
+	test_info->hang_slow = 0;
+	amdgpu_memcpy_draw_test(test_info);
+}
+
+
+void amdgpu_test_draw_helper(amdgpu_device_handle device_handle)
+{
+	shader_test_for_each(device_handle, AMDGPU_HW_IP_GFX, shader_test_draw_cb);
+}
+
+void amdgpu_test_draw_hang_helper(amdgpu_device_handle device_handle)
+{
+	shader_test_for_each(device_handle, AMDGPU_HW_IP_GFX, shader_test_draw_hang_cb);
+}
+
+void amdgpu_test_draw_hang_slow_helper(amdgpu_device_handle device_handle)
+{
+	shader_test_for_each(device_handle, AMDGPU_HW_IP_GFX, shader_test_draw_hang_slow_cb);
+}
diff --git a/tests/amdgpu/vce_tests.c b/tests/amdgpu/vce_tests.c
index 4e925cae..9aa0a8eb 100644
--- a/tests/amdgpu/vce_tests.c
+++ b/tests/amdgpu/vce_tests.c
@@ -96,7 +96,7 @@ CU_TestInfo vce_tests[] = {
 
 CU_BOOL suite_vce_tests_enable(void)
 {
-	uint32_t version, feature, asic_id;
+	uint32_t version, feature;
 	CU_BOOL ret_mv = CU_FALSE;
 
 	if (amdgpu_device_initialize(drm_amdgpu[0], &major_version,
@@ -107,7 +107,6 @@ CU_BOOL suite_vce_tests_enable(void)
 	chip_rev = device_handle->info.chip_rev;
 	chip_id = device_handle->info.chip_external_rev;
 	ids_flags = device_handle->info.ids_flags;
-	asic_id = device_handle->info.asic_id;
 
 	amdgpu_query_firmware_version(device_handle, AMDGPU_INFO_FW_VCE, 0,
 					  0, &version, &feature);
diff --git a/tests/amdgpu/vcn_tests.c b/tests/amdgpu/vcn_tests.c
index 15d573d3..c83fdb53 100644
--- a/tests/amdgpu/vcn_tests.c
+++ b/tests/amdgpu/vcn_tests.c
@@ -22,20 +22,65 @@
 */
 
 #include <stdio.h>
+#include <string.h>
 #include <inttypes.h>
+#include <unistd.h>
 
 #include "CUnit/Basic.h"
 
+#include <unistd.h>
 #include "util_math.h"
 
 #include "amdgpu_test.h"
 #include "amdgpu_drm.h"
 #include "amdgpu_internal.h"
 #include "decode_messages.h"
+#include "frame.h"
 
 #define IB_SIZE		4096
 #define MAX_RESOURCES	16
 
+#define DECODE_CMD_MSG_BUFFER                              0x00000000
+#define DECODE_CMD_DPB_BUFFER                              0x00000001
+#define DECODE_CMD_DECODING_TARGET_BUFFER                  0x00000002
+#define DECODE_CMD_FEEDBACK_BUFFER                         0x00000003
+#define DECODE_CMD_PROB_TBL_BUFFER                         0x00000004
+#define DECODE_CMD_SESSION_CONTEXT_BUFFER                  0x00000005
+#define DECODE_CMD_BITSTREAM_BUFFER                        0x00000100
+#define DECODE_CMD_IT_SCALING_TABLE_BUFFER                 0x00000204
+#define DECODE_CMD_CONTEXT_BUFFER                          0x00000206
+
+#define DECODE_IB_PARAM_DECODE_BUFFER                      (0x00000001)
+
+#define DECODE_CMDBUF_FLAGS_MSG_BUFFER                     (0x00000001)
+#define DECODE_CMDBUF_FLAGS_DPB_BUFFER                     (0x00000002)
+#define DECODE_CMDBUF_FLAGS_BITSTREAM_BUFFER               (0x00000004)
+#define DECODE_CMDBUF_FLAGS_DECODING_TARGET_BUFFER         (0x00000008)
+#define DECODE_CMDBUF_FLAGS_FEEDBACK_BUFFER                (0x00000010)
+#define DECODE_CMDBUF_FLAGS_IT_SCALING_BUFFER              (0x00000200)
+#define DECODE_CMDBUF_FLAGS_CONTEXT_BUFFER                 (0x00000800)
+#define DECODE_CMDBUF_FLAGS_PROB_TBL_BUFFER                (0x00001000)
+#define DECODE_CMDBUF_FLAGS_SESSION_CONTEXT_BUFFER         (0x00100000)
+
+static bool vcn_dec_sw_ring = false;
+static bool vcn_unified_ring = false;
+
+#define H264_NAL_TYPE_NON_IDR_SLICE 1
+#define H264_NAL_TYPE_DP_A_SLICE 2
+#define H264_NAL_TYPE_DP_B_SLICE 3
+#define H264_NAL_TYPE_DP_C_SLICE 0x4
+#define H264_NAL_TYPE_IDR_SLICE 0x5
+#define H264_NAL_TYPE_SEI 0x6
+#define H264_NAL_TYPE_SEQ_PARAM 0x7
+#define H264_NAL_TYPE_PIC_PARAM 0x8
+#define H264_NAL_TYPE_ACCESS_UNIT 0x9
+#define H264_NAL_TYPE_END_OF_SEQ 0xa
+#define H264_NAL_TYPE_END_OF_STREAM 0xb
+#define H264_NAL_TYPE_FILLER_DATA 0xc
+#define H264_NAL_TYPE_SEQ_EXTENSION 0xd
+
+#define H264_START_CODE 0x000001
+
 struct amdgpu_vcn_bo {
 	amdgpu_bo_handle handle;
 	amdgpu_va_handle va_handle;
@@ -44,6 +89,48 @@ struct amdgpu_vcn_bo {
 	uint8_t *ptr;
 };
 
+typedef struct rvcn_decode_buffer_s {
+	unsigned int valid_buf_flag;
+	unsigned int msg_buffer_address_hi;
+	unsigned int msg_buffer_address_lo;
+	unsigned int dpb_buffer_address_hi;
+	unsigned int dpb_buffer_address_lo;
+	unsigned int target_buffer_address_hi;
+	unsigned int target_buffer_address_lo;
+	unsigned int session_contex_buffer_address_hi;
+	unsigned int session_contex_buffer_address_lo;
+	unsigned int bitstream_buffer_address_hi;
+	unsigned int bitstream_buffer_address_lo;
+	unsigned int context_buffer_address_hi;
+	unsigned int context_buffer_address_lo;
+	unsigned int feedback_buffer_address_hi;
+	unsigned int feedback_buffer_address_lo;
+	unsigned int luma_hist_buffer_address_hi;
+	unsigned int luma_hist_buffer_address_lo;
+	unsigned int prob_tbl_buffer_address_hi;
+	unsigned int prob_tbl_buffer_address_lo;
+	unsigned int sclr_coeff_buffer_address_hi;
+	unsigned int sclr_coeff_buffer_address_lo;
+	unsigned int it_sclr_table_buffer_address_hi;
+	unsigned int it_sclr_table_buffer_address_lo;
+	unsigned int sclr_target_buffer_address_hi;
+	unsigned int sclr_target_buffer_address_lo;
+	unsigned int cenc_size_info_buffer_address_hi;
+	unsigned int cenc_size_info_buffer_address_lo;
+	unsigned int mpeg2_pic_param_buffer_address_hi;
+	unsigned int mpeg2_pic_param_buffer_address_lo;
+	unsigned int mpeg2_mb_control_buffer_address_hi;
+	unsigned int mpeg2_mb_control_buffer_address_lo;
+	unsigned int mpeg2_idct_coeff_buffer_address_hi;
+	unsigned int mpeg2_idct_coeff_buffer_address_lo;
+} rvcn_decode_buffer_t;
+
+typedef struct rvcn_decode_ib_package_s {
+	unsigned int package_size;
+	unsigned int package_type;
+} rvcn_decode_ib_package_t;
+
+
 struct amdgpu_vcn_reg {
 	uint32_t data0;
 	uint32_t data1;
@@ -52,6 +139,23 @@ struct amdgpu_vcn_reg {
 	uint32_t cntl;
 };
 
+typedef struct BufferInfo_t {
+	uint32_t numOfBitsInBuffer;
+	const uint8_t *decBuffer;
+	uint8_t decData;
+	uint32_t decBufferSize;
+	const uint8_t *end;
+} bufferInfo;
+
+typedef struct h264_decode_t {
+	uint8_t profile;
+	uint8_t level_idc;
+	uint8_t nal_ref_idc;
+	uint8_t nal_unit_type;
+	uint32_t pic_width, pic_height;
+	uint32_t slice_type;
+} h264_decode;
+
 static amdgpu_device_handle device_handle;
 static uint32_t major_version;
 static uint32_t minor_version;
@@ -60,18 +164,34 @@ static uint32_t chip_rev;
 static uint32_t chip_id;
 static uint32_t asic_id;
 static uint32_t chip_rev;
-static uint32_t chip_id;
+static struct amdgpu_vcn_bo enc_buf;
+static struct amdgpu_vcn_bo cpb_buf;
+static uint32_t enc_task_id;
 
 static amdgpu_context_handle context_handle;
 static amdgpu_bo_handle ib_handle;
 static amdgpu_va_handle ib_va_handle;
 static uint64_t ib_mc_address;
 static uint32_t *ib_cpu;
+static uint32_t *ib_checksum;
+static uint32_t *ib_size_in_dw;
+
+static rvcn_decode_buffer_t *decode_buffer;
+struct amdgpu_vcn_bo session_ctx_buf;
 
 static amdgpu_bo_handle resources[MAX_RESOURCES];
 static unsigned num_resources;
-static struct amdgpu_vcn_reg reg;
 
+static uint8_t vcn_reg_index;
+static struct amdgpu_vcn_reg reg[] = {
+	{0x81c4, 0x81c5, 0x81c3, 0x81ff, 0x81c6},
+	{0x504, 0x505, 0x503, 0x53f, 0x506},
+	{0x10, 0x11, 0xf, 0x29, 0x26d},
+};
+
+uint32_t gWidth, gHeight, gSliceType;
+static uint32_t vcn_ip_version_major;
+static uint32_t vcn_ip_version_minor;
 static void amdgpu_cs_vcn_dec_create(void);
 static void amdgpu_cs_vcn_dec_decode(void);
 static void amdgpu_cs_vcn_dec_destroy(void);
@@ -80,6 +200,22 @@ static void amdgpu_cs_vcn_enc_create(void);
 static void amdgpu_cs_vcn_enc_encode(void);
 static void amdgpu_cs_vcn_enc_destroy(void);
 
+static void amdgpu_cs_sq_head(uint32_t *base, int *offset, bool enc);
+static void amdgpu_cs_sq_ib_tail(uint32_t *end);
+static void h264_check_0s (bufferInfo * bufInfo, int count);
+static int32_t h264_se (bufferInfo * bufInfo);
+static inline uint32_t bs_read_u1(bufferInfo *bufinfo);
+static inline int bs_eof(bufferInfo *bufinfo);
+static inline uint32_t bs_read_u(bufferInfo* bufinfo, int n);
+static inline uint32_t bs_read_ue(bufferInfo* bufinfo);
+static uint32_t remove_03 (uint8_t *bptr, uint32_t len);
+static void scaling_list (uint32_t ix, uint32_t sizeOfScalingList, bufferInfo *bufInfo);
+static void h264_parse_sequence_parameter_set (h264_decode * dec, bufferInfo *bufInfo);
+static void h264_slice_header (h264_decode *dec, bufferInfo *bufInfo);
+static uint8_t h264_parse_nal (h264_decode *dec, bufferInfo *bufInfo);
+static uint32_t h264_find_next_start_code (uint8_t *pBuf, uint32_t bufLen);
+static int verify_checksum(uint8_t *buffer, uint32_t buffer_size);
+
 CU_TestInfo vcn_tests[] = {
 
 	{ "VCN DEC create",  amdgpu_cs_vcn_dec_create },
@@ -87,7 +223,7 @@ CU_TestInfo vcn_tests[] = {
 	{ "VCN DEC destroy",  amdgpu_cs_vcn_dec_destroy },
 
 	{ "VCN ENC create",  amdgpu_cs_vcn_enc_create },
-	{ "VCN ENC decode",  amdgpu_cs_vcn_enc_encode },
+	{ "VCN ENC encode",  amdgpu_cs_vcn_enc_encode },
 	{ "VCN ENC destroy",  amdgpu_cs_vcn_enc_destroy },
 	CU_TEST_INFO_NULL,
 };
@@ -95,6 +231,7 @@ CU_TestInfo vcn_tests[] = {
 CU_BOOL suite_vcn_tests_enable(void)
 {
 	struct drm_amdgpu_info_hw_ip info;
+	bool enc_ring, dec_ring;
 	int r;
 
 	if (amdgpu_device_initialize(drm_amdgpu[0], &major_version,
@@ -106,12 +243,31 @@ CU_BOOL suite_vcn_tests_enable(void)
 	chip_rev = device_handle->info.chip_rev;
 	chip_id = device_handle->info.chip_external_rev;
 
-	r = amdgpu_query_hw_ip_info(device_handle, AMDGPU_HW_IP_VCN_DEC, 0, &info);
+	r = amdgpu_query_hw_ip_info(device_handle, AMDGPU_HW_IP_VCN_ENC, 0, &info);
+	if (!r) {
+		vcn_ip_version_major = info.hw_ip_version_major;
+		vcn_ip_version_minor = info.hw_ip_version_minor;
+		enc_ring = !!info.available_rings;
+		/* in vcn 4.0 it re-uses encoding queue as unified queue */
+		if (vcn_ip_version_major >= 4) {
+			vcn_unified_ring = true;
+			vcn_dec_sw_ring = true;
+			dec_ring = enc_ring;
+		} else {
+			r = amdgpu_query_hw_ip_info(device_handle, AMDGPU_HW_IP_VCN_DEC, 0, &info);
+			dec_ring = !!info.available_rings;
+		}
+	}
 
 	if (amdgpu_device_deinitialize(device_handle))
-			return CU_FALSE;
+		return CU_FALSE;
+
+	if (r) {
+		printf("\n\nASIC query hw info failed\n");
+		return CU_FALSE;
+	}
 
-	if (r != 0 || !info.available_rings ||
+	if (!(dec_ring || enc_ring) ||
 	    (family_id < AMDGPU_FAMILY_RV &&
 	     (family_id == AMDGPU_FAMILY_AI &&
 	      (chip_id - chip_rev) < 0x32))) {  /* Arcturus */
@@ -119,52 +275,25 @@ CU_BOOL suite_vcn_tests_enable(void)
 		return CU_FALSE;
 	}
 
-	if (family_id == AMDGPU_FAMILY_AI) {
+	if (!dec_ring) {
+		amdgpu_set_test_active("VCN Tests", "VCN DEC create", CU_FALSE);
+		amdgpu_set_test_active("VCN Tests", "VCN DEC decode", CU_FALSE);
+		amdgpu_set_test_active("VCN Tests", "VCN DEC destroy", CU_FALSE);
+	}
+
+	if (family_id == AMDGPU_FAMILY_AI || !enc_ring) {
 		amdgpu_set_test_active("VCN Tests", "VCN ENC create", CU_FALSE);
-		amdgpu_set_test_active("VCN Tests", "VCN ENC decode", CU_FALSE);
+		amdgpu_set_test_active("VCN Tests", "VCN ENC encode", CU_FALSE);
 		amdgpu_set_test_active("VCN Tests", "VCN ENC destroy", CU_FALSE);
 	}
 
-	if (family_id == AMDGPU_FAMILY_RV) {
-		if (chip_id >= (chip_rev + 0x91)) {
-			reg.data0 = 0x504;
-			reg.data1 = 0x505;
-			reg.cmd = 0x503;
-			reg.nop = 0x53f;
-			reg.cntl = 0x506;
-		} else {
-			reg.data0 = 0x81c4;
-			reg.data1 = 0x81c5;
-			reg.cmd = 0x81c3;
-			reg.nop = 0x81ff;
-			reg.cntl = 0x81c6;
-		}
-	} else if (family_id == AMDGPU_FAMILY_NV) {
-		if (chip_id == (chip_rev + 0x28) ||
-		    chip_id == (chip_rev + 0x32) ||
-		    chip_id == (chip_rev + 0x3c) ||
-		    chip_id == (chip_rev + 0x46)) {
-			reg.data0 = 0x10;
-			reg.data1 = 0x11;
-			reg.cmd = 0xf;
-			reg.nop = 0x29;
-			reg.cntl = 0x26d;
-		}
-		else {
-			reg.data0 = 0x504;
-			reg.data1 = 0x505;
-			reg.cmd = 0x503;
-			reg.nop = 0x53f;
-			reg.cntl = 0x506;
-		}
-	} else if (family_id == AMDGPU_FAMILY_AI) {
-		reg.data0 = 0x10;
-		reg.data1 = 0x11;
-		reg.cmd = 0xf;
-		reg.nop = 0x29;
-		reg.cntl = 0x26d;
-	} else
-		return CU_FALSE;
+	if (vcn_ip_version_major == 1)
+		vcn_reg_index = 0;
+	else if (vcn_ip_version_major == 2 && vcn_ip_version_minor == 0)
+		vcn_reg_index = 1;
+	else if ((vcn_ip_version_major == 2 && vcn_ip_version_minor >= 5) ||
+				vcn_ip_version_major == 3)
+		vcn_reg_index = 2;
 
 	return CU_TRUE;
 }
@@ -214,6 +343,43 @@ int suite_vcn_tests_clean(void)
 	return CUE_SUCCESS;
 }
 
+static void amdgpu_cs_sq_head(uint32_t *base, int *offset, bool enc)
+{
+	/* signature */
+	*(base + (*offset)++) = 0x00000010;
+	*(base + (*offset)++) = 0x30000002;
+	ib_checksum = base + (*offset)++;
+	ib_size_in_dw = base + (*offset)++;
+
+	/* engine info */
+	*(base + (*offset)++) = 0x00000010;
+	*(base + (*offset)++) = 0x30000001;
+	*(base + (*offset)++) = enc ? 2 : 3;
+	*(base + (*offset)++) = 0x00000000;
+}
+
+static void amdgpu_cs_sq_ib_tail(uint32_t *end)
+{
+	uint32_t size_in_dw;
+	uint32_t checksum = 0;
+
+	/* if the pointers are invalid, no need to process */
+	if (ib_checksum == NULL || ib_size_in_dw == NULL)
+		return;
+
+	size_in_dw = end - ib_size_in_dw - 1;
+	*ib_size_in_dw = size_in_dw;
+	*(ib_size_in_dw + 4) = size_in_dw * sizeof(uint32_t);
+
+	for (int i = 0; i < size_in_dw; i++)
+		checksum += *(ib_checksum + 2 + i);
+
+	*ib_checksum = checksum;
+
+	ib_checksum = NULL;
+	ib_size_in_dw = NULL;
+}
+
 static int submit(unsigned ndw, unsigned ip)
 {
 	struct amdgpu_cs_request ibs_request = {0};
@@ -307,22 +473,98 @@ static void free_resource(struct amdgpu_vcn_bo *vcn_bo)
 
 static void vcn_dec_cmd(uint64_t addr, unsigned cmd, int *idx)
 {
-	ib_cpu[(*idx)++] = reg.data0;
-	ib_cpu[(*idx)++] = addr;
-	ib_cpu[(*idx)++] = reg.data1;
-	ib_cpu[(*idx)++] = addr >> 32;
-	ib_cpu[(*idx)++] = reg.cmd;
-	ib_cpu[(*idx)++] = cmd << 1;
+	if (vcn_dec_sw_ring == false) {
+		ib_cpu[(*idx)++] = reg[vcn_reg_index].data0;
+		ib_cpu[(*idx)++] = addr;
+		ib_cpu[(*idx)++] = reg[vcn_reg_index].data1;
+		ib_cpu[(*idx)++] = addr >> 32;
+		ib_cpu[(*idx)++] = reg[vcn_reg_index].cmd;
+		ib_cpu[(*idx)++] = cmd << 1;
+		return;
+	}
+
+	/* Support decode software ring message */
+	if (!(*idx)) {
+		rvcn_decode_ib_package_t *ib_header;
+
+		if (vcn_unified_ring)
+			amdgpu_cs_sq_head(ib_cpu, idx, false);
+
+		ib_header = (rvcn_decode_ib_package_t *)&ib_cpu[*idx];
+		ib_header->package_size = sizeof(struct rvcn_decode_buffer_s) +
+			sizeof(struct rvcn_decode_ib_package_s);
+
+		(*idx)++;
+		ib_header->package_type = (DECODE_IB_PARAM_DECODE_BUFFER);
+		(*idx)++;
+
+		decode_buffer = (rvcn_decode_buffer_t *)&(ib_cpu[*idx]);
+		*idx += sizeof(struct rvcn_decode_buffer_s) / 4;
+		memset(decode_buffer, 0, sizeof(struct rvcn_decode_buffer_s));
+	}
+
+	switch(cmd) {
+		case DECODE_CMD_MSG_BUFFER:
+			decode_buffer->valid_buf_flag |= DECODE_CMDBUF_FLAGS_MSG_BUFFER;
+			decode_buffer->msg_buffer_address_hi = (addr >> 32);
+			decode_buffer->msg_buffer_address_lo = (addr);
+		break;
+		case DECODE_CMD_DPB_BUFFER:
+			decode_buffer->valid_buf_flag |= (DECODE_CMDBUF_FLAGS_DPB_BUFFER);
+			decode_buffer->dpb_buffer_address_hi = (addr >> 32);
+			decode_buffer->dpb_buffer_address_lo = (addr);
+		break;
+		case DECODE_CMD_DECODING_TARGET_BUFFER:
+			decode_buffer->valid_buf_flag |= (DECODE_CMDBUF_FLAGS_DECODING_TARGET_BUFFER);
+			decode_buffer->target_buffer_address_hi = (addr >> 32);
+			decode_buffer->target_buffer_address_lo = (addr);
+		break;
+		case DECODE_CMD_FEEDBACK_BUFFER:
+			decode_buffer->valid_buf_flag |= (DECODE_CMDBUF_FLAGS_FEEDBACK_BUFFER);
+			decode_buffer->feedback_buffer_address_hi = (addr >> 32);
+			decode_buffer->feedback_buffer_address_lo = (addr);
+		break;
+		case DECODE_CMD_PROB_TBL_BUFFER:
+			decode_buffer->valid_buf_flag |= (DECODE_CMDBUF_FLAGS_PROB_TBL_BUFFER);
+			decode_buffer->prob_tbl_buffer_address_hi = (addr >> 32);
+			decode_buffer->prob_tbl_buffer_address_lo = (addr);
+		break;
+		case DECODE_CMD_SESSION_CONTEXT_BUFFER:
+			decode_buffer->valid_buf_flag |= (DECODE_CMDBUF_FLAGS_SESSION_CONTEXT_BUFFER);
+			decode_buffer->session_contex_buffer_address_hi = (addr >> 32);
+			decode_buffer->session_contex_buffer_address_lo = (addr);
+		break;
+		case DECODE_CMD_BITSTREAM_BUFFER:
+			decode_buffer->valid_buf_flag |= (DECODE_CMDBUF_FLAGS_BITSTREAM_BUFFER);
+			decode_buffer->bitstream_buffer_address_hi = (addr >> 32);
+			decode_buffer->bitstream_buffer_address_lo = (addr);
+		break;
+		case DECODE_CMD_IT_SCALING_TABLE_BUFFER:
+			decode_buffer->valid_buf_flag |= (DECODE_CMDBUF_FLAGS_IT_SCALING_BUFFER);
+			decode_buffer->it_sclr_table_buffer_address_hi = (addr >> 32);
+			decode_buffer->it_sclr_table_buffer_address_lo = (addr);
+		break;
+		case DECODE_CMD_CONTEXT_BUFFER:
+			decode_buffer->valid_buf_flag |= (DECODE_CMDBUF_FLAGS_CONTEXT_BUFFER);
+			decode_buffer->context_buffer_address_hi = (addr >> 32);
+			decode_buffer->context_buffer_address_lo = (addr);
+		break;
+		default:
+			printf("Not Support!\n");
+	}
 }
 
 static void amdgpu_cs_vcn_dec_create(void)
 {
 	struct amdgpu_vcn_bo msg_buf;
+	unsigned ip;
 	int len, r;
 
 	num_resources  = 0;
 	alloc_resource(&msg_buf, 4096, AMDGPU_GEM_DOMAIN_GTT);
+	alloc_resource(&session_ctx_buf, 32 * 4096, AMDGPU_GEM_DOMAIN_VRAM);
 	resources[num_resources++] = msg_buf.handle;
+	resources[num_resources++] = session_ctx_buf.handle;
 	resources[num_resources++] = ib_handle;
 
 	r = amdgpu_bo_cpu_map(msg_buf.handle, (void **)&msg_buf.ptr);
@@ -332,18 +574,31 @@ static void amdgpu_cs_vcn_dec_create(void)
 	memcpy(msg_buf.ptr, vcn_dec_create_msg, sizeof(vcn_dec_create_msg));
 
 	len = 0;
-	ib_cpu[len++] = reg.data0;
-	ib_cpu[len++] = msg_buf.addr;
-	ib_cpu[len++] = reg.data1;
-	ib_cpu[len++] = msg_buf.addr >> 32;
-	ib_cpu[len++] = reg.cmd;
-	ib_cpu[len++] = 0;
-	for (; len % 16; ) {
-		ib_cpu[len++] = reg.nop;
+
+	vcn_dec_cmd(session_ctx_buf.addr, 5, &len);
+	if (vcn_dec_sw_ring == true) {
+		vcn_dec_cmd(msg_buf.addr, 0, &len);
+	} else {
+		ib_cpu[len++] = reg[vcn_reg_index].data0;
+		ib_cpu[len++] = msg_buf.addr;
+		ib_cpu[len++] = reg[vcn_reg_index].data1;
+		ib_cpu[len++] = msg_buf.addr >> 32;
+		ib_cpu[len++] = reg[vcn_reg_index].cmd;
 		ib_cpu[len++] = 0;
+		for (; len % 16; ) {
+			ib_cpu[len++] = reg[vcn_reg_index].nop;
+			ib_cpu[len++] = 0;
+		}
 	}
 
-	r = submit(len, AMDGPU_HW_IP_VCN_DEC);
+	if (vcn_unified_ring) {
+		amdgpu_cs_sq_ib_tail(ib_cpu + len);
+		ip = AMDGPU_HW_IP_VCN_ENC;
+	} else
+		ip = AMDGPU_HW_IP_VCN_DEC;
+
+	r = submit(len, ip);
+
 	CU_ASSERT_EQUAL(r, 0);
 
 	free_resource(&msg_buf);
@@ -355,6 +610,7 @@ static void amdgpu_cs_vcn_dec_decode(void)
 	uint64_t msg_addr, fb_addr, bs_addr, dpb_addr, ctx_addr, dt_addr, it_addr, sum;
 	struct amdgpu_vcn_bo dec_buf;
 	int size, len, i, r;
+	unsigned ip;
 	uint8_t *dec;
 
 	size = 4*1024; /* msg */
@@ -364,7 +620,7 @@ static void amdgpu_cs_vcn_dec_decode(void)
 	size += ALIGN(dpb_size, 4*1024);
 	size += ALIGN(dt_size, 4*1024);
 
-	num_resources  = 0;
+	num_resources = 0;
 	alloc_resource(&dec_buf, size, AMDGPU_GEM_DOMAIN_GTT);
 	resources[num_resources++] = dec_buf.handle;
 	resources[num_resources++] = ib_handle;
@@ -399,6 +655,7 @@ static void amdgpu_cs_vcn_dec_decode(void)
 	dt_addr = ALIGN(dpb_addr + dpb_size, 4*1024);
 
 	len = 0;
+	vcn_dec_cmd(session_ctx_buf.addr, 0x5, &len);
 	vcn_dec_cmd(msg_addr, 0x0, &len);
 	vcn_dec_cmd(dpb_addr, 0x1, &len);
 	vcn_dec_cmd(dt_addr, 0x2, &len);
@@ -407,14 +664,22 @@ static void amdgpu_cs_vcn_dec_decode(void)
 	vcn_dec_cmd(it_addr, 0x204, &len);
 	vcn_dec_cmd(ctx_addr, 0x206, &len);
 
-	ib_cpu[len++] = reg.cntl;
-	ib_cpu[len++] = 0x1;
-	for (; len % 16; ) {
-		ib_cpu[len++] = reg.nop;
-		ib_cpu[len++] = 0;
+	if (vcn_dec_sw_ring == false) {
+		ib_cpu[len++] = reg[vcn_reg_index].cntl;
+		ib_cpu[len++] = 0x1;
+		for (; len % 16; ) {
+			ib_cpu[len++] = reg[vcn_reg_index].nop;
+			ib_cpu[len++] = 0;
+		}
 	}
 
-	r = submit(len, AMDGPU_HW_IP_VCN_DEC);
+	if (vcn_unified_ring) {
+		amdgpu_cs_sq_ib_tail(ib_cpu + len);
+		ip = AMDGPU_HW_IP_VCN_ENC;
+	} else
+		ip = AMDGPU_HW_IP_VCN_DEC;
+
+	r = submit(len, ip);
 	CU_ASSERT_EQUAL(r, 0);
 
 	for (i = 0, sum = 0; i < dt_size; ++i)
@@ -428,9 +693,10 @@ static void amdgpu_cs_vcn_dec_decode(void)
 static void amdgpu_cs_vcn_dec_destroy(void)
 {
 	struct amdgpu_vcn_bo msg_buf;
+	unsigned ip;
 	int len, r;
 
-	num_resources  = 0;
+	num_resources = 0;
 	alloc_resource(&msg_buf, 1024, AMDGPU_GEM_DOMAIN_GTT);
 	resources[num_resources++] = msg_buf.handle;
 	resources[num_resources++] = ib_handle;
@@ -442,34 +708,945 @@ static void amdgpu_cs_vcn_dec_destroy(void)
 	memcpy(msg_buf.ptr, vcn_dec_destroy_msg, sizeof(vcn_dec_destroy_msg));
 
 	len = 0;
-	ib_cpu[len++] = reg.data0;
-	ib_cpu[len++] = msg_buf.addr;
-	ib_cpu[len++] = reg.data1;
-	ib_cpu[len++] = msg_buf.addr >> 32;
-	ib_cpu[len++] = reg.cmd;
-	ib_cpu[len++] = 0;
-	for (; len % 16; ) {
-		ib_cpu[len++] = reg.nop;
+	vcn_dec_cmd(session_ctx_buf.addr, 5, &len);
+	if (vcn_dec_sw_ring == true) {
+		vcn_dec_cmd(msg_buf.addr, 0, &len);
+	} else {
+		ib_cpu[len++] = reg[vcn_reg_index].data0;
+		ib_cpu[len++] = msg_buf.addr;
+		ib_cpu[len++] = reg[vcn_reg_index].data1;
+		ib_cpu[len++] = msg_buf.addr >> 32;
+		ib_cpu[len++] = reg[vcn_reg_index].cmd;
 		ib_cpu[len++] = 0;
+		for (; len % 16; ) {
+			ib_cpu[len++] = reg[vcn_reg_index].nop;
+			ib_cpu[len++] = 0;
+		}
 	}
 
-	r = submit(len, AMDGPU_HW_IP_VCN_DEC);
+	if (vcn_unified_ring) {
+		amdgpu_cs_sq_ib_tail(ib_cpu + len);
+		ip = AMDGPU_HW_IP_VCN_ENC;
+	} else
+		ip = AMDGPU_HW_IP_VCN_DEC;
+
+	r = submit(len, ip);
 	CU_ASSERT_EQUAL(r, 0);
 
 	free_resource(&msg_buf);
+	free_resource(&session_ctx_buf);
 }
 
 static void amdgpu_cs_vcn_enc_create(void)
 {
-	/* TODO */
+	int len, r;
+	uint32_t *p_task_size = NULL;
+	uint32_t task_offset = 0, st_offset;
+	uint32_t *st_size = NULL;
+	unsigned width = 160, height = 128, buf_size;
+	uint32_t fw_maj = 1, fw_min = 9;
+
+	if (vcn_ip_version_major == 2) {
+		fw_maj = 1;
+		fw_min = 1;
+	} else if (vcn_ip_version_major == 3) {
+		fw_maj = 1;
+		fw_min = 0;
+	}
+
+	gWidth = width;
+	gHeight = height;
+	buf_size = ALIGN(width, 256) * ALIGN(height, 32) * 3 / 2;
+	enc_task_id = 1;
+
+	num_resources = 0;
+	alloc_resource(&enc_buf, 128 * 1024, AMDGPU_GEM_DOMAIN_GTT);
+	alloc_resource(&cpb_buf, buf_size * 2, AMDGPU_GEM_DOMAIN_GTT);
+	resources[num_resources++] = enc_buf.handle;
+	resources[num_resources++] = cpb_buf.handle;
+	resources[num_resources++] = ib_handle;
+
+	r = amdgpu_bo_cpu_map(enc_buf.handle, (void**)&enc_buf.ptr);
+	memset(enc_buf.ptr, 0, 128 * 1024);
+	r = amdgpu_bo_cpu_unmap(enc_buf.handle);
+
+	r = amdgpu_bo_cpu_map(cpb_buf.handle, (void**)&enc_buf.ptr);
+	memset(enc_buf.ptr, 0, buf_size * 2);
+	r = amdgpu_bo_cpu_unmap(cpb_buf.handle);
+
+	len = 0;
+
+	if (vcn_unified_ring)
+		amdgpu_cs_sq_head(ib_cpu, &len, true);
+
+	/* session info */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000001;	/* RENCODE_IB_PARAM_SESSION_INFO */
+	ib_cpu[len++] = ((fw_maj << 16) | (fw_min << 0));
+	ib_cpu[len++] = enc_buf.addr >> 32;
+	ib_cpu[len++] = enc_buf.addr;
+	ib_cpu[len++] = 1;	/* RENCODE_ENGINE_TYPE_ENCODE; */
+	*st_size = (len - st_offset) * 4;
+
+	/* task info */
+	task_offset = len;
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000002;	/* RENCODE_IB_PARAM_TASK_INFO */
+	p_task_size = &ib_cpu[len++];
+	ib_cpu[len++] = enc_task_id++;	/* task_id */
+	ib_cpu[len++] = 0;	/* feedback */
+	*st_size = (len - st_offset) * 4;
+
+	/* op init */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x01000001;	/* RENCODE_IB_OP_INITIALIZE */
+	*st_size = (len - st_offset) * 4;
+
+	/* session_init */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000003;	/* RENCODE_IB_PARAM_SESSION_INIT */
+	ib_cpu[len++] = 1;	/* RENCODE_ENCODE_STANDARD_H264 */
+	ib_cpu[len++] = width;
+	ib_cpu[len++] = height;
+	ib_cpu[len++] = 0;
+	ib_cpu[len++] = 0;
+	ib_cpu[len++] = 0;	/* pre encode mode */
+	ib_cpu[len++] = 0;	/* chroma enabled : false */
+	ib_cpu[len++] = 0;
+	ib_cpu[len++] = 0;
+	*st_size = (len - st_offset) * 4;
+
+	/* slice control */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00200001;	/* RENCODE_H264_IB_PARAM_SLICE_CONTROL */
+	ib_cpu[len++] = 0;	/* RENCODE_H264_SLICE_CONTROL_MODE_FIXED_MBS */
+	ib_cpu[len++] = ALIGN(width, 16) / 16 * ALIGN(height, 16) / 16;
+	*st_size = (len - st_offset) * 4;
+
+	/* enc spec misc */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00200002;	/* RENCODE_H264_IB_PARAM_SPEC_MISC */
+	ib_cpu[len++] = 0;	/* constrained intra pred flag */
+	ib_cpu[len++] = 0;	/* cabac enable */
+	ib_cpu[len++] = 0;	/* cabac init idc */
+	ib_cpu[len++] = 1;	/* half pel enabled */
+	ib_cpu[len++] = 1;	/* quarter pel enabled */
+	ib_cpu[len++] = 100;	/* BASELINE profile */
+	ib_cpu[len++] = 11;	/* level */
+	if (vcn_ip_version_major >= 3) {
+		ib_cpu[len++] = 0;	/* b_picture_enabled */
+		ib_cpu[len++] = 0;	/* weighted_bipred_idc */
+	}
+	*st_size = (len - st_offset) * 4;
+
+	/* deblocking filter */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00200004;	/* RENCODE_H264_IB_PARAM_DEBLOCKING_FILTER */
+	ib_cpu[len++] = 0;	/* disable deblocking filter idc */
+	ib_cpu[len++] = 0;	/* alpha c0 offset */
+	ib_cpu[len++] = 0;	/* tc offset */
+	ib_cpu[len++] = 0;	/* cb offset */
+	ib_cpu[len++] = 0;	/* cr offset */
+	*st_size = (len - st_offset) * 4;
+
+	/* layer control */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000004;	/* RENCODE_IB_PARAM_LAYER_CONTROL */
+	ib_cpu[len++] = 1;	/* max temporal layer */
+	ib_cpu[len++] = 1;	/* no of temporal layer */
+	*st_size = (len - st_offset) * 4;
+
+	/* rc_session init */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000006;	/* RENCODE_IB_PARAM_RATE_CONTROL_SESSION_INIT */
+	ib_cpu[len++] = 0;	/* rate control */
+	ib_cpu[len++] = 48;	/* vbv buffer level */
+	*st_size = (len - st_offset) * 4;
+
+	/* quality params */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000009;	/* RENCODE_IB_PARAM_QUALITY_PARAMS */
+	ib_cpu[len++] = 0;	/* vbaq mode */
+	ib_cpu[len++] = 0;	/* scene change sensitivity */
+	ib_cpu[len++] = 0;	/* scene change min idr interval */
+	ib_cpu[len++] = 0;
+	if (vcn_ip_version_major >= 3)
+		ib_cpu[len++] = 0;
+	*st_size = (len - st_offset) * 4;
+
+	/* layer select */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000005;	/* RENCODE_IB_PARAM_LAYER_SELECT */
+	ib_cpu[len++] = 0;	/* temporal layer */
+	*st_size = (len - st_offset) * 4;
+
+	/* rc layer init */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000007;	/* RENCODE_IB_PARAM_RATE_CONTROL_LAYER_INIT */
+	ib_cpu[len++] = 0;
+	ib_cpu[len++] = 0;
+	ib_cpu[len++] = 25;
+	ib_cpu[len++] = 1;
+	ib_cpu[len++] = 0x01312d00;
+	ib_cpu[len++] = 0;
+	ib_cpu[len++] = 0;
+	ib_cpu[len++] = 0;
+	*st_size = (len - st_offset) * 4;
+
+	/* layer select */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000005;	/* RENCODE_IB_PARAM_LAYER_SELECT */
+	ib_cpu[len++] = 0;	/* temporal layer */
+	*st_size = (len - st_offset) * 4;
+
+	/* rc per pic */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000008;	/* RENCODE_IB_PARAM_RATE_CONTROL_PER_PICTURE */
+	ib_cpu[len++] = 20;
+	ib_cpu[len++] = 0;
+	ib_cpu[len++] = 51;
+	ib_cpu[len++] = 0;
+	ib_cpu[len++] = 1;
+	ib_cpu[len++] = 0;
+	ib_cpu[len++] = 1;
+	ib_cpu[len++] = 0;
+	*st_size = (len - st_offset) * 4;
+
+	/* op init rc */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x01000004;	/* RENCODE_IB_OP_INIT_RC */
+	*st_size = (len - st_offset) * 4;
+
+	/* op init rc vbv */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x01000005;	/* RENCODE_IB_OP_INIT_RC_VBV_BUFFER_LEVEL */
+	*st_size = (len - st_offset) * 4;
+
+	*p_task_size = (len - task_offset) * 4;
+
+	if (vcn_unified_ring)
+		amdgpu_cs_sq_ib_tail(ib_cpu + len);
+
+	r = submit(len, AMDGPU_HW_IP_VCN_ENC);
+	CU_ASSERT_EQUAL(r, 0);
+}
+
+static int32_t h264_se (bufferInfo * bufInfo)
+{
+	uint32_t ret;
+
+	ret = bs_read_ue (bufInfo);
+	if ((ret & 0x1) == 0) {
+		ret >>= 1;
+		int32_t temp = 0 - ret;
+		return temp;
+	}
+
+	return (ret + 1) >> 1;
+}
+
+static void h264_check_0s (bufferInfo * bufInfo, int count)
+{
+	uint32_t val;
+
+	val = bs_read_u (bufInfo, count);
+	if (val != 0) {
+		printf ("field error - %d bits should be 0 is %x\n", count, val);
+	}
+}
+
+static inline int bs_eof(bufferInfo * bufinfo)
+{
+	if (bufinfo->decBuffer >= bufinfo->end)
+		return 1;
+	else
+		return 0;
+}
+
+static inline uint32_t bs_read_u1(bufferInfo *bufinfo)
+{
+	uint32_t r = 0;
+	uint32_t temp = 0;
+
+	bufinfo->numOfBitsInBuffer--;
+	if (! bs_eof(bufinfo)) {
+		temp = (((bufinfo->decData)) >> bufinfo->numOfBitsInBuffer);
+		r = temp & 0x01;
+	}
+
+	if (bufinfo->numOfBitsInBuffer == 0) {
+		bufinfo->decBuffer++;
+		bufinfo->decData = *bufinfo->decBuffer;
+		bufinfo->numOfBitsInBuffer = 8;
+	}
+
+	return r;
+}
+
+static inline uint32_t bs_read_u(bufferInfo* bufinfo, int n)
+{
+	uint32_t r = 0;
+	int i;
+
+	for (i = 0; i < n; i++) {
+		r |= ( bs_read_u1(bufinfo) << ( n - i - 1 ) );
+	}
+
+	return r;
+}
+
+static inline uint32_t bs_read_ue(bufferInfo* bufinfo)
+{
+	int32_t r = 0;
+	int i = 0;
+
+	while( (bs_read_u1(bufinfo) == 0) && (i < 32) && (!bs_eof(bufinfo))) {
+		i++;
+	}
+	r = bs_read_u(bufinfo, i);
+	r += (1 << i) - 1;
+	return r;
+}
+
+static uint32_t remove_03 (uint8_t * bptr, uint32_t len)
+{
+	uint32_t nal_len = 0;
+	while (nal_len + 2 < len) {
+		if (bptr[0] == 0 && bptr[1] == 0 && bptr[2] == 3) {
+			bptr += 2;
+			nal_len += 2;
+			len--;
+			memmove (bptr, bptr + 1, len - nal_len);
+		} else {
+			bptr++;
+			nal_len++;
+		}
+	}
+	return len;
+}
+
+static void scaling_list (uint32_t ix, uint32_t sizeOfScalingList, bufferInfo * bufInfo)
+{
+	uint32_t lastScale = 8, nextScale = 8;
+	uint32_t jx;
+	int deltaScale;
+
+	for (jx = 0; jx < sizeOfScalingList; jx++) {
+		if (nextScale != 0) {
+			deltaScale = h264_se (bufInfo);
+			nextScale = (lastScale + deltaScale + 256) % 256;
+		}
+		if (nextScale == 0) {
+			lastScale = lastScale;
+		} else {
+			lastScale = nextScale;
+		}
+	}
+}
+
+static void h264_parse_sequence_parameter_set (h264_decode * dec, bufferInfo * bufInfo)
+{
+	uint32_t temp;
+
+	dec->profile = bs_read_u (bufInfo, 8);
+	bs_read_u (bufInfo, 1);		/* constaint_set0_flag */
+	bs_read_u (bufInfo, 1);		/* constaint_set1_flag */
+	bs_read_u (bufInfo, 1);		/* constaint_set2_flag */
+	bs_read_u (bufInfo, 1);		/* constaint_set3_flag */
+	bs_read_u (bufInfo, 1);		/* constaint_set4_flag */
+	bs_read_u (bufInfo, 1);		/* constaint_set5_flag */
+
+
+	h264_check_0s (bufInfo, 2);
+	dec->level_idc = bs_read_u (bufInfo, 8);
+	bs_read_ue (bufInfo);	/* SPS id*/
+
+	if (dec->profile == 100 || dec->profile == 110 ||
+		dec->profile == 122 || dec->profile == 144) {
+		uint32_t chroma_format_idc = bs_read_ue (bufInfo);
+		if (chroma_format_idc == 3) {
+			bs_read_u (bufInfo, 1);	/* residual_colour_transform_flag */
+		}
+		bs_read_ue (bufInfo);	/* bit_depth_luma_minus8 */
+		bs_read_ue (bufInfo);	/* bit_depth_chroma_minus8 */
+		bs_read_u (bufInfo, 1);	/* qpprime_y_zero_transform_bypass_flag */
+		uint32_t seq_scaling_matrix_present_flag = bs_read_u (bufInfo, 1);
+
+		if (seq_scaling_matrix_present_flag) {
+			for (uint32_t ix = 0; ix < 8; ix++) {
+				temp = bs_read_u (bufInfo, 1);
+				if (temp) {
+					scaling_list (ix, ix < 6 ? 16 : 64, bufInfo);
+				}
+			}
+		}
+	}
+
+	bs_read_ue (bufInfo);	/* log2_max_frame_num_minus4 */
+	uint32_t pic_order_cnt_type = bs_read_ue (bufInfo);
+
+	if (pic_order_cnt_type == 0) {
+		bs_read_ue (bufInfo);	/* log2_max_pic_order_cnt_lsb_minus4 */
+	} else if (pic_order_cnt_type == 1) {
+		bs_read_u (bufInfo, 1);	/* delta_pic_order_always_zero_flag */
+		h264_se (bufInfo);	/* offset_for_non_ref_pic */
+		h264_se (bufInfo);	/* offset_for_top_to_bottom_field */
+		temp = bs_read_ue (bufInfo);
+		for (uint32_t ix = 0; ix < temp; ix++) {
+			 h264_se (bufInfo);	/* offset_for_ref_frame[index] */
+		}
+	}
+	bs_read_ue (bufInfo);	/* num_ref_frames */
+	bs_read_u (bufInfo, 1);	/* gaps_in_frame_num_flag */
+	uint32_t PicWidthInMbs = bs_read_ue (bufInfo) + 1;
+
+	dec->pic_width = PicWidthInMbs * 16;
+	uint32_t PicHeightInMapUnits = bs_read_ue (bufInfo) + 1;
+
+	dec->pic_height = PicHeightInMapUnits * 16;
+	uint32_t frame_mbs_only_flag = bs_read_u (bufInfo, 1);
+	if (!frame_mbs_only_flag) {
+		bs_read_u (bufInfo, 1);	/* mb_adaptive_frame_field_flag */
+	}
+	bs_read_u (bufInfo, 1);	/* direct_8x8_inference_flag */
+	temp = bs_read_u (bufInfo, 1);
+	if (temp) {
+		bs_read_ue (bufInfo);	/* frame_crop_left_offset */
+		bs_read_ue (bufInfo);	/* frame_crop_right_offset */
+		bs_read_ue (bufInfo);	/* frame_crop_top_offset */
+		bs_read_ue (bufInfo);	/* frame_crop_bottom_offset */
+	}
+	temp = bs_read_u (bufInfo, 1);	/* VUI Parameters  */
+}
+
+static void h264_slice_header (h264_decode * dec, bufferInfo * bufInfo)
+{
+	uint32_t temp;
+
+	bs_read_ue (bufInfo);	/* first_mb_in_slice */
+	temp = bs_read_ue (bufInfo);
+	dec->slice_type = ((temp > 5) ? (temp - 5) : temp);
+}
+
+static uint8_t h264_parse_nal (h264_decode * dec, bufferInfo * bufInfo)
+{
+	uint8_t type = 0;
+
+	h264_check_0s (bufInfo, 1);
+	dec->nal_ref_idc = bs_read_u (bufInfo, 2);
+	dec->nal_unit_type = type = bs_read_u (bufInfo, 5);
+	switch (type)
+	{
+	case H264_NAL_TYPE_NON_IDR_SLICE:
+	case H264_NAL_TYPE_IDR_SLICE:
+		h264_slice_header (dec, bufInfo);
+		break;
+	case H264_NAL_TYPE_SEQ_PARAM:
+		h264_parse_sequence_parameter_set (dec, bufInfo);
+		break;
+	case H264_NAL_TYPE_PIC_PARAM:
+	case H264_NAL_TYPE_SEI:
+	case H264_NAL_TYPE_ACCESS_UNIT:
+	case H264_NAL_TYPE_SEQ_EXTENSION:
+		/* NOP */
+		break;
+	default:
+		printf ("Nal type unknown %d \n ", type);
+		break;
+	}
+	return type;
+}
+
+static uint32_t h264_find_next_start_code (uint8_t * pBuf, uint32_t bufLen)
+{
+	uint32_t val;
+	uint32_t offset, startBytes;
+
+	offset = startBytes = 0;
+	if (pBuf[0] == 0 && pBuf[1] == 0 && pBuf[2] == 0 && pBuf[3] == 1) {
+		pBuf += 4;
+		offset = 4;
+		startBytes = 1;
+	} else if (pBuf[0] == 0 && pBuf[1] == 0 && pBuf[2] == 1) {
+		pBuf += 3;
+		offset = 3;
+		startBytes = 1;
+	}
+	val = 0xffffffff;
+	while (offset < bufLen - 3) {
+		val <<= 8;
+		val |= *pBuf++;
+		offset++;
+		if (val == H264_START_CODE)
+			return offset - 4;
+
+		if ((val & 0x00ffffff) == H264_START_CODE)
+			return offset - 3;
+	}
+	if (bufLen - offset <= 3 && startBytes == 0) {
+		startBytes = 0;
+		return 0;
+	}
+
+	return offset;
+}
+
+static int verify_checksum(uint8_t *buffer, uint32_t buffer_size)
+{
+	uint32_t buffer_pos = 0;
+	int done = 0;
+	h264_decode dec;
+
+	memset(&dec, 0, sizeof(h264_decode));
+	do {
+		uint32_t ret;
+
+		ret = h264_find_next_start_code (buffer + buffer_pos,
+				 buffer_size - buffer_pos);
+		if (ret == 0) {
+			done = 1;
+			if (buffer_pos == 0) {
+				fprintf (stderr,
+				 "couldn't find start code in buffer from 0\n");
+			}
+		} else {
+		/* have a complete NAL from buffer_pos to end */
+			if (ret > 3) {
+				uint32_t nal_len;
+				bufferInfo bufinfo;
+
+				nal_len = remove_03 (buffer + buffer_pos, ret);
+				bufinfo.decBuffer = buffer + buffer_pos + (buffer[buffer_pos + 2] == 1 ? 3 : 4);
+				bufinfo.decBufferSize = (nal_len - (buffer[buffer_pos + 2] == 1 ? 3 : 4)) * 8;
+				bufinfo.end = buffer + buffer_pos + nal_len;
+				bufinfo.numOfBitsInBuffer = 8;
+				bufinfo.decData = *bufinfo.decBuffer;
+				h264_parse_nal (&dec, &bufinfo);
+			}
+			buffer_pos += ret;	/*  buffer_pos points to next code */
+		}
+	} while (done == 0);
+
+	if ((dec.pic_width == gWidth) &&
+		(dec.pic_height == gHeight) &&
+		(dec.slice_type == gSliceType))
+	    return 0;
+	else
+		return -1;
+}
+
+static void check_result(struct amdgpu_vcn_bo fb_buf, struct amdgpu_vcn_bo bs_buf, int frame_type)
+{
+	uint32_t *fb_ptr;
+	uint8_t *bs_ptr;
+	uint32_t size;
+	int r;
+/* 	uint64_t s[3] = {0, 1121279001727, 1059312481445}; */
+
+	r = amdgpu_bo_cpu_map(fb_buf.handle, (void **)&fb_buf.ptr);
+	CU_ASSERT_EQUAL(r, 0);
+	fb_ptr = (uint32_t*)fb_buf.ptr;
+	size = fb_ptr[6];
+	r = amdgpu_bo_cpu_unmap(fb_buf.handle);
+	CU_ASSERT_EQUAL(r, 0);
+	r = amdgpu_bo_cpu_map(bs_buf.handle, (void **)&bs_buf.ptr);
+	CU_ASSERT_EQUAL(r, 0);
+
+	bs_ptr = (uint8_t*)bs_buf.ptr;
+	r = verify_checksum(bs_ptr, size);
+	CU_ASSERT_EQUAL(r, 0);
+	r = amdgpu_bo_cpu_unmap(bs_buf.handle);
+
+	CU_ASSERT_EQUAL(r, 0);
+}
+
+static void amdgpu_cs_vcn_ib_zero_count(int *len, int num)
+{
+	for (int i = 0; i < num; i++)
+		ib_cpu[(*len)++] = 0;
+}
+
+static void amdgpu_cs_vcn_enc_encode_frame(int frame_type)
+{
+	struct amdgpu_vcn_bo bs_buf, fb_buf, input_buf;
+	int len, r;
+	unsigned width = 160, height = 128, buf_size;
+	uint32_t *p_task_size = NULL;
+	uint32_t task_offset = 0, st_offset;
+	uint32_t *st_size = NULL;
+	uint32_t fw_maj = 1, fw_min = 9;
+
+	if (vcn_ip_version_major == 2) {
+		fw_maj = 1;
+		fw_min = 1;
+	} else if (vcn_ip_version_major == 3) {
+		fw_maj = 1;
+		fw_min = 0;
+	}
+	gSliceType = frame_type;
+	buf_size = ALIGN(width, 256) * ALIGN(height, 32) * 3 / 2;
+
+	num_resources = 0;
+	alloc_resource(&bs_buf, 4096, AMDGPU_GEM_DOMAIN_GTT);
+	alloc_resource(&fb_buf, 4096, AMDGPU_GEM_DOMAIN_GTT);
+	alloc_resource(&input_buf, buf_size, AMDGPU_GEM_DOMAIN_GTT);
+	resources[num_resources++] = enc_buf.handle;
+	resources[num_resources++] = cpb_buf.handle;
+	resources[num_resources++] = bs_buf.handle;
+	resources[num_resources++] = fb_buf.handle;
+	resources[num_resources++] = input_buf.handle;
+	resources[num_resources++] = ib_handle;
+
+
+	r = amdgpu_bo_cpu_map(bs_buf.handle, (void**)&bs_buf.ptr);
+	memset(bs_buf.ptr, 0, 4096);
+	r = amdgpu_bo_cpu_unmap(bs_buf.handle);
+
+	r = amdgpu_bo_cpu_map(fb_buf.handle, (void**)&fb_buf.ptr);
+	memset(fb_buf.ptr, 0, 4096);
+	r = amdgpu_bo_cpu_unmap(fb_buf.handle);
+
+	r = amdgpu_bo_cpu_map(input_buf.handle, (void **)&input_buf.ptr);
+	CU_ASSERT_EQUAL(r, 0);
+
+	for (int i = 0; i < ALIGN(height, 32) * 3 / 2; i++)
+		memcpy(input_buf.ptr + i * ALIGN(width, 256), frame + i * width, width);
+
+	r = amdgpu_bo_cpu_unmap(input_buf.handle);
+	CU_ASSERT_EQUAL(r, 0);
+
+	len = 0;
+
+	if (vcn_unified_ring)
+		amdgpu_cs_sq_head(ib_cpu, &len, true);
+
+	/* session info */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000001;	/* RENCODE_IB_PARAM_SESSION_INFO */
+	ib_cpu[len++] = ((fw_maj << 16) | (fw_min << 0));
+	ib_cpu[len++] = enc_buf.addr >> 32;
+	ib_cpu[len++] = enc_buf.addr;
+	ib_cpu[len++] = 1;	/* RENCODE_ENGINE_TYPE_ENCODE */;
+	*st_size = (len - st_offset) * 4;
+
+	/* task info */
+	task_offset = len;
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000002;	/* RENCODE_IB_PARAM_TASK_INFO */
+	p_task_size = &ib_cpu[len++];
+	ib_cpu[len++] = enc_task_id++;	/* task_id */
+	ib_cpu[len++] = 1;	/* feedback */
+	*st_size = (len - st_offset) * 4;
+
+	if (frame_type == 2) {
+		/* sps */
+		st_offset = len;
+		st_size = &ib_cpu[len++];	/* size */
+		if(vcn_ip_version_major == 1)
+			ib_cpu[len++] = 0x00000020;	/* RENCODE_IB_PARAM_DIRECT_OUTPUT_NALU vcn 1 */
+		else
+			ib_cpu[len++] = 0x0000000a;	/* RENCODE_IB_PARAM_DIRECT_OUTPUT_NALU other vcn */
+		ib_cpu[len++] = 0x00000002;	/* RENCODE_DIRECT_OUTPUT_NALU_TYPE_SPS */
+		ib_cpu[len++] = 0x00000011;	/* sps len */
+		ib_cpu[len++] = 0x00000001;	/* start code */
+		ib_cpu[len++] = 0x6764440b;
+		ib_cpu[len++] = 0xac54c284;
+		ib_cpu[len++] = 0x68078442;
+		ib_cpu[len++] = 0x37000000;
+		*st_size = (len - st_offset) * 4;
+
+		/* pps */
+		st_offset = len;
+		st_size = &ib_cpu[len++];	/* size */
+		if(vcn_ip_version_major == 1)
+			ib_cpu[len++] = 0x00000020;	/* RENCODE_IB_PARAM_DIRECT_OUTPUT_NALU vcn 1*/
+		else
+			ib_cpu[len++] = 0x0000000a;	/* RENCODE_IB_PARAM_DIRECT_OUTPUT_NALU other vcn*/
+		ib_cpu[len++] = 0x00000003;	/* RENCODE_DIRECT_OUTPUT_NALU_TYPE_PPS */
+		ib_cpu[len++] = 0x00000008;	/* pps len */
+		ib_cpu[len++] = 0x00000001;	/* start code */
+		ib_cpu[len++] = 0x68ce3c80;
+		*st_size = (len - st_offset) * 4;
+	}
+
+	/* slice header */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	if(vcn_ip_version_major == 1)
+		ib_cpu[len++] = 0x0000000a; /* RENCODE_IB_PARAM_SLICE_HEADER vcn 1 */
+	else
+		ib_cpu[len++] = 0x0000000b; /* RENCODE_IB_PARAM_SLICE_HEADER other vcn */
+	if (frame_type == 2) {
+		ib_cpu[len++] = 0x65000000;
+		ib_cpu[len++] = 0x11040000;
+	} else {
+		ib_cpu[len++] = 0x41000000;
+		ib_cpu[len++] = 0x34210000;
+	}
+	ib_cpu[len++] = 0xe0000000;
+	amdgpu_cs_vcn_ib_zero_count(&len, 13);
+
+	ib_cpu[len++] = 0x00000001;
+	ib_cpu[len++] = 0x00000008;
+	ib_cpu[len++] = 0x00020000;
+	ib_cpu[len++] = 0x00000000;
+	ib_cpu[len++] = 0x00000001;
+	ib_cpu[len++] = 0x00000015;
+	ib_cpu[len++] = 0x00020001;
+	ib_cpu[len++] = 0x00000000;
+	ib_cpu[len++] = 0x00000001;
+	ib_cpu[len++] = 0x00000003;
+	amdgpu_cs_vcn_ib_zero_count(&len, 22);
+	*st_size = (len - st_offset) * 4;
+
+	/* encode params */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	if(vcn_ip_version_major == 1)
+		ib_cpu[len++] = 0x0000000b;	/* RENCODE_IB_PARAM_ENCODE_PARAMS vcn 1 */
+	else
+		ib_cpu[len++] = 0x0000000f;	/* RENCODE_IB_PARAM_ENCODE_PARAMS other vcn */
+	ib_cpu[len++] = frame_type;
+	ib_cpu[len++] = 0x0001f000;
+	ib_cpu[len++] = input_buf.addr >> 32;
+	ib_cpu[len++] = input_buf.addr;
+	ib_cpu[len++] = (input_buf.addr + ALIGN(width, 256) * ALIGN(height, 32)) >> 32;
+	ib_cpu[len++] = input_buf.addr + ALIGN(width, 256) * ALIGN(height, 32);
+	ib_cpu[len++] = 0x00000100;
+	ib_cpu[len++] = 0x00000080;
+	ib_cpu[len++] = 0x00000000;
+	ib_cpu[len++] = 0xffffffff;
+	ib_cpu[len++] = 0x00000000;
+	*st_size = (len - st_offset) * 4;
+
+	/* encode params h264 */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00200003;	/* RENCODE_H264_IB_PARAM_ENCODE_PARAMS */
+	if (vcn_ip_version_major <= 2) {
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0xffffffff;
+	} else {
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0xffffffff;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0xffffffff;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000001;
+	}
+	*st_size = (len - st_offset) * 4;
+
+	/* encode context */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	if(vcn_ip_version_major == 1)
+		ib_cpu[len++] = 0x0000000d;	/* ENCODE_CONTEXT_BUFFER  vcn 1 */
+	else
+		ib_cpu[len++] = 0x00000011;	/* ENCODE_CONTEXT_BUFFER  other vcn */
+	ib_cpu[len++] = cpb_buf.addr >> 32;
+	ib_cpu[len++] = cpb_buf.addr;
+	ib_cpu[len++] = 0x00000000;	/* swizzle mode */
+	ib_cpu[len++] = 0x00000100;	/* luma pitch */
+	ib_cpu[len++] = 0x00000100;	/* chroma pitch */
+	ib_cpu[len++] = 0x00000002; /* no reconstructed picture */
+	ib_cpu[len++] = 0x00000000;	/* reconstructed pic 1 luma offset */
+	ib_cpu[len++] = ALIGN(width, 256) * ALIGN(height, 32);	/* pic1 chroma offset */
+	if(vcn_ip_version_major == 4)
+		amdgpu_cs_vcn_ib_zero_count(&len, 2);
+	ib_cpu[len++] = ALIGN(width, 256) * ALIGN(height, 32) * 3 / 2;	/* pic2 luma offset */
+	ib_cpu[len++] = ALIGN(width, 256) * ALIGN(height, 32) * 5 / 2;	/* pic2 chroma offset */
+
+	amdgpu_cs_vcn_ib_zero_count(&len, 280);
+	*st_size = (len - st_offset) * 4;
+
+	/* bitstream buffer */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	if(vcn_ip_version_major == 1)
+		ib_cpu[len++] = 0x0000000e;	/* VIDEO_BITSTREAM_BUFFER vcn 1 */
+	else
+		ib_cpu[len++] = 0x00000012;	/* VIDEO_BITSTREAM_BUFFER other vcn */
+
+	ib_cpu[len++] = 0x00000000;	/* mode */
+	ib_cpu[len++] = bs_buf.addr >> 32;
+	ib_cpu[len++] = bs_buf.addr;
+	ib_cpu[len++] = 0x0001f000;
+	ib_cpu[len++] = 0x00000000;
+	*st_size = (len - st_offset) * 4;
+
+	/* feedback */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	if(vcn_ip_version_major == 1)
+		ib_cpu[len++] = 0x00000010;	/* FEEDBACK_BUFFER vcn 1 */
+	else
+		ib_cpu[len++] = 0x00000015;	/* FEEDBACK_BUFFER vcn 2,3 */
+	ib_cpu[len++] = 0x00000000;
+	ib_cpu[len++] = fb_buf.addr >> 32;
+	ib_cpu[len++] = fb_buf.addr;
+	ib_cpu[len++] = 0x00000010;
+	ib_cpu[len++] = 0x00000028;
+	*st_size = (len - st_offset) * 4;
+
+	/* intra refresh */
+	st_offset = len;
+	st_size = &ib_cpu[len++];
+	if(vcn_ip_version_major == 1)
+		ib_cpu[len++] = 0x0000000c;	/* INTRA_REFRESH vcn 1 */
+	else
+		ib_cpu[len++] = 0x00000010;	/* INTRA_REFRESH vcn 2,3 */
+	ib_cpu[len++] = 0x00000000;
+	ib_cpu[len++] = 0x00000000;
+	ib_cpu[len++] = 0x00000000;
+	*st_size = (len - st_offset) * 4;
+
+	if(vcn_ip_version_major != 1) {
+		/* Input Format */
+		st_offset = len;
+		st_size = &ib_cpu[len++];
+		ib_cpu[len++] = 0x0000000c;
+		ib_cpu[len++] = 0x00000000;	/* RENCODE_COLOR_VOLUME_G22_BT709 */
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;	/* RENCODE_COLOR_BIT_DEPTH_8_BIT */
+		ib_cpu[len++] = 0x00000000;	/* RENCODE_COLOR_PACKING_FORMAT_NV12 */
+		*st_size = (len - st_offset) * 4;
+
+		/* Output Format */
+		st_offset = len;
+		st_size = &ib_cpu[len++];
+		ib_cpu[len++] = 0x0000000d;
+		ib_cpu[len++] = 0x00000000;	/* RENCODE_COLOR_VOLUME_G22_BT709 */
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;
+		ib_cpu[len++] = 0x00000000;	/* RENCODE_COLOR_BIT_DEPTH_8_BIT */
+		*st_size = (len - st_offset) * 4;
+	}
+	/* op_speed */
+	st_offset = len;
+	st_size = &ib_cpu[len++];
+	ib_cpu[len++] = 0x01000006;	/* SPEED_ENCODING_MODE */
+	*st_size = (len - st_offset) * 4;
+
+	/* op_enc */
+	st_offset = len;
+	st_size = &ib_cpu[len++];
+	ib_cpu[len++] = 0x01000003;
+	*st_size = (len - st_offset) * 4;
+
+	*p_task_size = (len - task_offset) * 4;
+
+	if (vcn_unified_ring)
+		amdgpu_cs_sq_ib_tail(ib_cpu + len);
+
+	r = submit(len, AMDGPU_HW_IP_VCN_ENC);
+	CU_ASSERT_EQUAL(r, 0);
+
+	/* check result */
+	check_result(fb_buf, bs_buf, frame_type);
+
+	free_resource(&fb_buf);
+	free_resource(&bs_buf);
+	free_resource(&input_buf);
 }
 
 static void amdgpu_cs_vcn_enc_encode(void)
 {
-	/* TODO */
+	amdgpu_cs_vcn_enc_encode_frame(2);	/* IDR frame */
 }
 
 static void amdgpu_cs_vcn_enc_destroy(void)
 {
-	/* TODO */
+	int len = 0, r;
+	uint32_t *p_task_size = NULL;
+	uint32_t task_offset = 0, st_offset;
+	uint32_t *st_size = NULL;
+	uint32_t fw_maj = 1, fw_min = 9;
+
+	if (vcn_ip_version_major == 2) {
+		fw_maj = 1;
+		fw_min = 1;
+	} else if (vcn_ip_version_major == 3) {
+		fw_maj = 1;
+		fw_min = 0;
+	}
+
+	num_resources = 0;
+/* 	alloc_resource(&enc_buf, 128 * 1024, AMDGPU_GEM_DOMAIN_GTT); */
+	resources[num_resources++] = enc_buf.handle;
+	resources[num_resources++] = ib_handle;
+
+	if (vcn_unified_ring)
+		amdgpu_cs_sq_head(ib_cpu, &len, true);
+
+	/* session info */
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000001;	/* RENCODE_IB_PARAM_SESSION_INFO */
+	ib_cpu[len++] = ((fw_maj << 16) | (fw_min << 0));
+	ib_cpu[len++] = enc_buf.addr >> 32;
+	ib_cpu[len++] = enc_buf.addr;
+	ib_cpu[len++] = 1;	/* RENCODE_ENGINE_TYPE_ENCODE; */
+	*st_size = (len - st_offset) * 4;
+
+	/* task info */
+	task_offset = len;
+	st_offset = len;
+	st_size = &ib_cpu[len++];	/* size */
+	ib_cpu[len++] = 0x00000002;	/* RENCODE_IB_PARAM_TASK_INFO */
+	p_task_size = &ib_cpu[len++];
+	ib_cpu[len++] = enc_task_id++;	/* task_id */
+	ib_cpu[len++] = 0;	/* feedback */
+	*st_size = (len - st_offset) * 4;
+
+	/*  op close */
+	st_offset = len;
+	st_size = &ib_cpu[len++];
+	ib_cpu[len++] = 0x01000002;	/* RENCODE_IB_OP_CLOSE_SESSION */
+	*st_size = (len - st_offset) * 4;
+
+	*p_task_size = (len - task_offset) * 4;
+
+	if (vcn_unified_ring)
+		amdgpu_cs_sq_ib_tail(ib_cpu + len);
+
+	r = submit(len, AMDGPU_HW_IP_VCN_ENC);
+	CU_ASSERT_EQUAL(r, 0);
+
+	free_resource(&cpb_buf);
+	free_resource(&enc_buf);
 }
diff --git a/tests/drmdevice.c b/tests/drmdevice.c
index f1c1cd3a..b4b62d9c 100644
--- a/tests/drmdevice.c
+++ b/tests/drmdevice.c
@@ -142,7 +142,7 @@ main(void)
         for (int j = 0; j < DRM_NODE_MAX; j++) {
             if (devices[i]->available_nodes & 1 << j) {
                 printf("--- Opening device node %s ---\n", devices[i]->nodes[j]);
-                fd = open(devices[i]->nodes[j], O_RDONLY | O_CLOEXEC, 0);
+                fd = open(devices[i]->nodes[j], O_RDONLY | O_CLOEXEC);
                 if (fd < 0) {
                     printf("Failed - %s (%d)\n", strerror(errno), errno);
                     continue;
diff --git a/tests/exynos/exynos_fimg2d_test.c b/tests/exynos/exynos_fimg2d_test.c
index 99bb9233..b5cf3600 100644
--- a/tests/exynos/exynos_fimg2d_test.c
+++ b/tests/exynos/exynos_fimg2d_test.c
@@ -31,7 +31,6 @@
 #include <unistd.h>
 
 #include <sys/mman.h>
-#include <linux/stddef.h>
 
 #include <xf86drm.h>
 #include <xf86drmMode.h>
diff --git a/tests/modeprint/modeprint.c b/tests/modeprint/modeprint.c
index f424f19d..0f644c74 100644
--- a/tests/modeprint/modeprint.c
+++ b/tests/modeprint/modeprint.c
@@ -113,7 +113,7 @@ static int printProperty(int fd, drmModeResPtr res, drmModePropertyPtr props, ui
 
 	} else {
 		for (j = 0; j < props->count_enums; j++) {
-			printf("\t\t%" PRId64 " = %s\n", props->enums[j].value, props->enums[j].name);
+			printf("\t\t%" PRIu64" = %s\n", (uint64_t)props->enums[j].value, props->enums[j].name);
 			if (props->enums[j].value == value)
 				name = props->enums[j].name;
 		}
@@ -135,7 +135,7 @@ static int printConnector(int fd, drmModeResPtr res, drmModeConnectorPtr connect
 	drmModePropertyPtr props;
 	const char *connector_type_name = NULL;
 
-	connector_type_name = util_lookup_connector_type_name(connector->connector_type);
+	connector_type_name = drmModeGetConnectorTypeName(connector->connector_type);
 
 	if (connector_type_name)
 		printf("Connector: %s-%d\n", connector_type_name,
diff --git a/tests/modetest/Android.bp b/tests/modetest/Android.bp
index 02a17fe9..87120121 100644
--- a/tests/modetest/Android.bp
+++ b/tests/modetest/Android.bp
@@ -9,7 +9,7 @@ package {
 
 build = ["Android.sources.bp"]
 
-cc_test {
+cc_binary {
     name: "modetest",
     defaults: [
         "libdrm_defaults",
diff --git a/tests/modetest/Makefile.sources b/tests/modetest/Makefile.sources
deleted file mode 100644
index 399af0df..00000000
--- a/tests/modetest/Makefile.sources
+++ /dev/null
@@ -1,6 +0,0 @@
-MODETEST_FILES := \
-	buffers.c \
-	buffers.h \
-	cursor.c \
-	cursor.h \
-	modetest.c
diff --git a/tests/modetest/buffers.c b/tests/modetest/buffers.c
index 8a8d9e01..576e2cc7 100644
--- a/tests/modetest/buffers.c
+++ b/tests/modetest/buffers.c
@@ -37,6 +37,7 @@
 
 #include "libdrm_macros.h"
 #include "xf86drm.h"
+#include "xf86drmMode.h"
 
 #include "buffers.h"
 
@@ -44,10 +45,9 @@ struct bo
 {
 	int fd;
 	void *ptr;
-	size_t size;
-	size_t offset;
-	size_t pitch;
-	unsigned handle;
+	uint64_t size;
+	uint32_t pitch;
+	uint32_t handle;
 };
 
 /* -----------------------------------------------------------------------------
@@ -57,7 +57,6 @@ struct bo
 static struct bo *
 bo_create_dumb(int fd, unsigned int width, unsigned int height, unsigned int bpp)
 {
-	struct drm_mode_create_dumb arg;
 	struct bo *bo;
 	int ret;
 
@@ -67,12 +66,8 @@ bo_create_dumb(int fd, unsigned int width, unsigned int height, unsigned int bpp
 		return NULL;
 	}
 
-	memset(&arg, 0, sizeof(arg));
-	arg.bpp = bpp;
-	arg.width = width;
-	arg.height = height;
-
-	ret = drmIoctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &arg);
+	ret = drmModeCreateDumbBuffer(fd, width, height, bpp, 0, &bo->handle,
+				      &bo->pitch, &bo->size);
 	if (ret) {
 		fprintf(stderr, "failed to create dumb buffer: %s\n",
 			strerror(errno));
@@ -81,28 +76,22 @@ bo_create_dumb(int fd, unsigned int width, unsigned int height, unsigned int bpp
 	}
 
 	bo->fd = fd;
-	bo->handle = arg.handle;
-	bo->size = arg.size;
-	bo->pitch = arg.pitch;
 
 	return bo;
 }
 
 static int bo_map(struct bo *bo, void **out)
 {
-	struct drm_mode_map_dumb arg;
 	void *map;
 	int ret;
+	uint64_t offset;
 
-	memset(&arg, 0, sizeof(arg));
-	arg.handle = bo->handle;
-
-	ret = drmIoctl(bo->fd, DRM_IOCTL_MODE_MAP_DUMB, &arg);
+	ret = drmModeMapDumbBuffer(bo->fd, bo->handle, &offset);
 	if (ret)
 		return ret;
 
 	map = drm_mmap(0, bo->size, PROT_READ | PROT_WRITE, MAP_SHARED,
-		       bo->fd, arg.offset);
+		       bo->fd, offset);
 	if (map == MAP_FAILED)
 		return -EINVAL;
 
@@ -135,16 +124,36 @@ bo_create(int fd, unsigned int format,
 	int ret;
 
 	switch (format) {
+	case DRM_FORMAT_C1:
+		bpp = 1;
+		break;
+
+	case DRM_FORMAT_C2:
+		bpp = 2;
+		break;
+
+	case DRM_FORMAT_C4:
+		bpp = 4;
+		break;
+
 	case DRM_FORMAT_C8:
 	case DRM_FORMAT_NV12:
 	case DRM_FORMAT_NV21:
 	case DRM_FORMAT_NV16:
 	case DRM_FORMAT_NV61:
+	case DRM_FORMAT_NV24:
+	case DRM_FORMAT_NV42:
 	case DRM_FORMAT_YUV420:
 	case DRM_FORMAT_YVU420:
 		bpp = 8;
 		break;
 
+	case DRM_FORMAT_NV15:
+	case DRM_FORMAT_NV20:
+	case DRM_FORMAT_NV30:
+		bpp = 10;
+		break;
+
 	case DRM_FORMAT_ARGB4444:
 	case DRM_FORMAT_XRGB4444:
 	case DRM_FORMAT_ABGR4444:
@@ -155,6 +164,7 @@ bo_create(int fd, unsigned int format,
 	case DRM_FORMAT_BGRX4444:
 	case DRM_FORMAT_ARGB1555:
 	case DRM_FORMAT_XRGB1555:
+	case DRM_FORMAT_XRGB1555 | DRM_FORMAT_BIG_ENDIAN:
 	case DRM_FORMAT_ABGR1555:
 	case DRM_FORMAT_XBGR1555:
 	case DRM_FORMAT_RGBA5551:
@@ -162,6 +172,7 @@ bo_create(int fd, unsigned int format,
 	case DRM_FORMAT_BGRA5551:
 	case DRM_FORMAT_BGRX5551:
 	case DRM_FORMAT_RGB565:
+	case DRM_FORMAT_RGB565 | DRM_FORMAT_BIG_ENDIAN:
 	case DRM_FORMAT_BGR565:
 	case DRM_FORMAT_UYVY:
 	case DRM_FORMAT_VYUY:
@@ -209,6 +220,7 @@ bo_create(int fd, unsigned int format,
 	switch (format) {
 	case DRM_FORMAT_NV12:
 	case DRM_FORMAT_NV21:
+	case DRM_FORMAT_NV15:
 	case DRM_FORMAT_YUV420:
 	case DRM_FORMAT_YVU420:
 		virtual_height = height * 3 / 2;
@@ -216,9 +228,16 @@ bo_create(int fd, unsigned int format,
 
 	case DRM_FORMAT_NV16:
 	case DRM_FORMAT_NV61:
+	case DRM_FORMAT_NV20:
 		virtual_height = height * 2;
 		break;
 
+	case DRM_FORMAT_NV24:
+	case DRM_FORMAT_NV42:
+	case DRM_FORMAT_NV30:
+		virtual_height = height * 3;
+		break;
+
 	default:
 		virtual_height = height;
 		break;
@@ -255,6 +274,8 @@ bo_create(int fd, unsigned int format,
 	case DRM_FORMAT_NV21:
 	case DRM_FORMAT_NV16:
 	case DRM_FORMAT_NV61:
+	case DRM_FORMAT_NV15:
+	case DRM_FORMAT_NV20:
 		offsets[0] = 0;
 		handles[0] = bo->handle;
 		pitches[0] = bo->pitch;
@@ -266,6 +287,20 @@ bo_create(int fd, unsigned int format,
 		planes[1] = virtual + offsets[1];
 		break;
 
+	case DRM_FORMAT_NV24:
+	case DRM_FORMAT_NV42:
+	case DRM_FORMAT_NV30:
+		offsets[0] = 0;
+		handles[0] = bo->handle;
+		pitches[0] = bo->pitch;
+		pitches[1] = pitches[0] * 2;
+		offsets[1] = pitches[0] * height;
+		handles[1] = bo->handle;
+
+		planes[0] = virtual;
+		planes[1] = virtual + offsets[1];
+		break;
+
 	case DRM_FORMAT_YUV420:
 	case DRM_FORMAT_YVU420:
 		offsets[0] = 0;
@@ -283,6 +318,9 @@ bo_create(int fd, unsigned int format,
 		planes[2] = virtual + offsets[2];
 		break;
 
+	case DRM_FORMAT_C1:
+	case DRM_FORMAT_C2:
+	case DRM_FORMAT_C4:
 	case DRM_FORMAT_C8:
 	case DRM_FORMAT_ARGB4444:
 	case DRM_FORMAT_XRGB4444:
@@ -294,6 +332,7 @@ bo_create(int fd, unsigned int format,
 	case DRM_FORMAT_BGRX4444:
 	case DRM_FORMAT_ARGB1555:
 	case DRM_FORMAT_XRGB1555:
+	case DRM_FORMAT_XRGB1555 | DRM_FORMAT_BIG_ENDIAN:
 	case DRM_FORMAT_ABGR1555:
 	case DRM_FORMAT_XBGR1555:
 	case DRM_FORMAT_RGBA5551:
@@ -301,6 +340,7 @@ bo_create(int fd, unsigned int format,
 	case DRM_FORMAT_BGRA5551:
 	case DRM_FORMAT_BGRX5551:
 	case DRM_FORMAT_RGB565:
+	case DRM_FORMAT_RGB565 | DRM_FORMAT_BIG_ENDIAN:
 	case DRM_FORMAT_BGR565:
 	case DRM_FORMAT_BGR888:
 	case DRM_FORMAT_RGB888:
@@ -340,16 +380,31 @@ bo_create(int fd, unsigned int format,
 
 void bo_destroy(struct bo *bo)
 {
-	struct drm_mode_destroy_dumb arg;
 	int ret;
 
-	memset(&arg, 0, sizeof(arg));
-	arg.handle = bo->handle;
-
-	ret = drmIoctl(bo->fd, DRM_IOCTL_MODE_DESTROY_DUMB, &arg);
+	ret = drmModeDestroyDumbBuffer(bo->fd, bo->handle);
 	if (ret)
 		fprintf(stderr, "failed to destroy dumb buffer: %s\n",
 			strerror(errno));
 
 	free(bo);
 }
+
+void bo_dump(struct bo *bo, const char *filename)
+{
+	FILE *fp;
+
+	if (!bo || !filename)
+		return;
+
+	fp = fopen(filename, "wb");
+	if (fp) {
+		void *addr;
+
+		bo_map(bo, &addr);
+		printf("Dumping buffer %p to file %s.\n", bo->ptr, filename);
+		fwrite(bo->ptr, 1, bo->size, fp);
+		bo_unmap(bo);
+		fclose(fp);
+	}
+}
diff --git a/tests/modetest/buffers.h b/tests/modetest/buffers.h
index 7f95396b..cbd54e9e 100644
--- a/tests/modetest/buffers.h
+++ b/tests/modetest/buffers.h
@@ -36,5 +36,6 @@ struct bo *bo_create(int fd, unsigned int format,
 		   unsigned int handles[4], unsigned int pitches[4],
 		   unsigned int offsets[4], enum util_fill_pattern pattern);
 void bo_destroy(struct bo *bo);
+void bo_dump(struct bo *bo, const char *filename);
 
 #endif
diff --git a/tests/modetest/meson.build b/tests/modetest/meson.build
index 23d84a1d..5ed1638c 100644
--- a/tests/modetest/meson.build
+++ b/tests/modetest/meson.build
@@ -25,5 +25,6 @@ modetest = executable(
   include_directories : [inc_root, inc_tests, inc_drm],
   dependencies : [dep_threads, dep_cairo],
   link_with : [libdrm, libutil],
+  link_args: '-lm',
   install : with_install_tests,
 )
diff --git a/tests/modetest/modetest.c b/tests/modetest/modetest.c
index 5fd22f79..d9e761e6 100644
--- a/tests/modetest/modetest.c
+++ b/tests/modetest/modetest.c
@@ -70,6 +70,7 @@
 
 static enum util_fill_pattern primary_fill = UTIL_PATTERN_SMPTE;
 static enum util_fill_pattern secondary_fill = UTIL_PATTERN_TILES;
+static drmModeModeInfo user_mode;
 
 struct crtc {
 	drmModeCrtc *crtc;
@@ -128,6 +129,7 @@ struct device {
 
 	int use_atomic;
 	drmModeAtomicReq *req;
+	int32_t writeback_fence_fd;
 };
 
 static inline int64_t U642I64(uint64_t val)
@@ -137,8 +139,19 @@ static inline int64_t U642I64(uint64_t val)
 
 static float mode_vrefresh(drmModeModeInfo *mode)
 {
-	return  mode->clock * 1000.00
-			/ (mode->htotal * mode->vtotal);
+	unsigned int num, den;
+
+	num = mode->clock;
+	den = mode->htotal * mode->vtotal;
+
+	if (mode->flags & DRM_MODE_FLAG_INTERLACE)
+		num *= 2;
+	if (mode->flags & DRM_MODE_FLAG_DBLSCAN)
+		den *= 2;
+	if (mode->vscan > 1)
+		den *= mode->vscan;
+
+	return num * 1000.00 / den;
 }
 
 #define bit_name_fn(res)					\
@@ -187,11 +200,9 @@ static bit_name_fn(mode_flag)
 
 static void dump_fourcc(uint32_t fourcc)
 {
-	printf(" %c%c%c%c",
-		fourcc,
-		fourcc >> 8,
-		fourcc >> 16,
-		fourcc >> 24);
+	char *name = drmGetFormatName(fourcc);
+	printf(" %s", name);
+	free(name);
 }
 
 static void dump_encoders(struct device *dev)
@@ -319,7 +330,7 @@ static void dump_in_formats(struct device *dev, uint32_t blob_id)
 			printf(": ");
 		}
 
-		printf(" %s", modifier_to_string(iter.mod));
+		printf(" %s(0x%"PRIx64")", modifier_to_string(iter.mod), iter.mod);
 	}
 
 	printf("\n");
@@ -376,7 +387,7 @@ static void dump_prop(struct device *dev, drmModePropertyPtr prop,
 		printf("\t\tenums:");
 		for (i = 0; i < prop->count_enums; i++)
 			printf(" %s=%"PRIu64, prop->enums[i].name,
-			       prop->enums[i].value);
+			       (uint64_t)prop->enums[i].value);
 		printf("\n");
 	} else if (drm_property_type_is(prop, DRM_MODE_PROP_BITMASK)) {
 		printf("\t\tvalues:");
@@ -656,7 +667,7 @@ static struct resources *get_resources(struct device *dev)
 		int num;
 
 		num = asprintf(&connector->name, "%s-%u",
-			 util_lookup_connector_type_name(conn->connector_type),
+			 drmModeGetConnectorTypeName(conn->connector_type),
 			 conn->connector_type_id);
 		if (num < 0)
 			goto error;
@@ -806,13 +817,15 @@ struct pipe_arg {
 	unsigned int num_cons;
 	uint32_t crtc_id;
 	char mode_str[64];
-	char format_str[5];
+	char format_str[8]; /* need to leave room for "_BE" and terminating \0 */
 	float vrefresh;
 	unsigned int fourcc;
 	drmModeModeInfo *mode;
 	struct crtc *crtc;
 	unsigned int fb_id[2], current_fb_id;
 	struct timeval start;
+	unsigned int out_fb_id;
+	struct bo *out_bo;
 
 	int swap_count;
 };
@@ -828,7 +841,7 @@ struct plane_arg {
 	unsigned int old_fb_id;
 	struct bo *bo;
 	struct bo *old_bo;
-	char format_str[5]; /* need to leave room for terminating \0 */
+	char format_str[8]; /* need to leave room for "_BE" and terminating \0 */
 	unsigned int fourcc;
 };
 
@@ -841,7 +854,25 @@ connector_find_mode(struct device *dev, uint32_t con_id, const char *mode_str,
 	int i;
 
 	connector = get_connector_by_id(dev, con_id);
-	if (!connector || !connector->count_modes)
+	if (!connector)
+		return NULL;
+
+	if (strchr(mode_str, ',')) {
+		i = sscanf(mode_str, "%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu",
+			     &user_mode.hdisplay, &user_mode.hsync_start,
+			     &user_mode.hsync_end, &user_mode.htotal,
+			     &user_mode.vdisplay, &user_mode.vsync_start,
+			     &user_mode.vsync_end, &user_mode.vtotal);
+		if (i == 8) {
+			user_mode.clock = roundf(user_mode.htotal * user_mode.vtotal * vrefresh / 1000);
+			user_mode.vrefresh = roundf(vrefresh);
+			snprintf(user_mode.name, sizeof(user_mode.name), "custom%dx%d", user_mode.hdisplay, user_mode.vdisplay);
+
+			return &user_mode;
+		}
+	}
+
+	if (!connector->count_modes)
 		return NULL;
 
 	/* Pick by Index */
@@ -1042,7 +1073,7 @@ static bool set_property(struct device *dev, struct property_arg *p)
 
 	if (ret < 0)
 		fprintf(stderr, "failed to set %s %i property %s to %" PRIu64 ": %s\n",
-			obj_type, p->obj_id, p->name, p->value, strerror(errno));
+			obj_type, p->obj_id, p->name, p->value, strerror(-ret));
 
 	return true;
 }
@@ -1118,15 +1149,23 @@ static bool add_property_optional(struct device *dev, uint32_t obj_id,
 static void set_gamma(struct device *dev, unsigned crtc_id, unsigned fourcc)
 {
 	unsigned blob_id = 0;
+	const struct util_format_info *info;
 	/* TODO: support 1024-sized LUTs, when the use-case arises */
 	struct drm_color_lut gamma_lut[256];
 	int i, ret;
 
-	if (fourcc == DRM_FORMAT_C8) {
-		/* TODO: Add C8 support for more patterns */
-		util_smpte_c8_gamma(256, gamma_lut);
+	info = util_format_info_find(fourcc);
+	if (info->ncolors) {
+		memset(gamma_lut, 0, sizeof(gamma_lut));
+		/* TODO: Add index support for more patterns */
+		util_smpte_fill_lut(info->ncolors, gamma_lut);
 		drmModeCreatePropertyBlob(dev->fd, gamma_lut, sizeof(gamma_lut), &blob_id);
 	} else {
+		/*
+		 * Initialize gamma_lut to a linear table for the legacy API below.
+		 * The modern property API resets to a linear/pass-thru table if blob_id
+		 * is 0, hence no PropertyBlob is created here.
+		 */
 		for (i = 0; i < 256; i++) {
 			gamma_lut[i].red =
 			gamma_lut[i].green =
@@ -1137,6 +1176,7 @@ static void set_gamma(struct device *dev, unsigned crtc_id, unsigned fourcc)
 	add_property_optional(dev, crtc_id, "DEGAMMA_LUT", 0);
 	add_property_optional(dev, crtc_id, "CTM", 0);
 	if (!add_property_optional(dev, crtc_id, "GAMMA_LUT", blob_id)) {
+		/* If we can't add the GAMMA_LUT property, try the legacy API. */
 		uint16_t r[256], g[256], b[256];
 
 		for (i = 0; i < 256; i++) {
@@ -1146,7 +1186,7 @@ static void set_gamma(struct device *dev, unsigned crtc_id, unsigned fourcc)
 		}
 
 		ret = drmModeCrtcSetGamma(dev->fd, crtc_id, 256, r, g, b);
-		if (ret)
+		if (ret && errno != ENOSYS)
 			fprintf(stderr, "failed to set gamma: %s\n", strerror(errno));
 	}
 }
@@ -1443,6 +1483,24 @@ static int pipe_resolve_connectors(struct device *dev, struct pipe_arg *pipe)
 	return 0;
 }
 
+static bool pipe_has_writeback_connector(struct device *dev, struct pipe_arg *pipes,
+		unsigned int count)
+{
+	drmModeConnector *connector;
+	unsigned int i, j;
+
+	for (j = 0; j < count; j++) {
+		struct pipe_arg *pipe = &pipes[j];
+
+		for (i = 0; i < pipe->num_cons; i++) {
+			connector = get_connector_by_id(dev, pipe->con_ids[i]);
+			if (connector && connector->connector_type == DRM_MODE_CONNECTOR_WRITEBACK)
+				return true;
+		}
+	}
+	return false;
+}
+
 static int pipe_attempt_connector(struct device *dev, drmModeConnector *con,
 		struct pipe_arg *pipe)
 {
@@ -1505,7 +1563,8 @@ static int pipe_find_preferred(struct device *dev, struct pipe_arg **out_pipes)
 
 	for (i = 0; i < res->count_connectors; i++) {
 		con = res->connectors[i].connector;
-		if (!con || con->connection != DRM_MODE_CONNECTED)
+		if (!con || con->connection != DRM_MODE_CONNECTED ||
+		    con->connector_type == DRM_MODE_CONNECTOR_WRITEBACK)
 			continue;
 		connected++;
 	}
@@ -1552,32 +1611,35 @@ static struct plane *get_primary_plane_by_crtc(struct device *dev, struct crtc *
 	return NULL;
 }
 
-static void set_mode(struct device *dev, struct pipe_arg *pipes, unsigned int count)
+static unsigned int set_mode(struct device *dev, struct pipe_arg **pipe_args, unsigned int count)
 {
 	unsigned int i, j;
 	int ret, x = 0;
 	int preferred = count == 0;
+	struct pipe_arg *pipes;
 
-	for (i = 0; i < count; i++) {
-		struct pipe_arg *pipe = &pipes[i];
-
-		ret = pipe_resolve_connectors(dev, pipe);
-		if (ret < 0)
-			return;
-
-		ret = pipe_find_crtc_and_mode(dev, pipe);
-		if (ret < 0)
-			continue;
-	}
 	if (preferred) {
-		struct pipe_arg *pipe_args;
-
-		count = pipe_find_preferred(dev, &pipe_args);
+		count = pipe_find_preferred(dev, pipe_args);
 		if (!count) {
 			fprintf(stderr, "can't find any preferred connector/mode.\n");
-			return;
+			return 0;
+		}
+
+		pipes = *pipe_args;
+	} else {
+		pipes = *pipe_args;
+
+		for (i = 0; i < count; i++) {
+			struct pipe_arg *pipe = &pipes[i];
+
+			ret = pipe_resolve_connectors(dev, pipe);
+			if (ret < 0)
+				return 0;
+
+			ret = pipe_find_crtc_and_mode(dev, pipe);
+			if (ret < 0)
+				continue;
 		}
-		pipes = pipe_args;
 	}
 
 	if (!dev->use_atomic) {
@@ -1604,7 +1666,7 @@ static void set_mode(struct device *dev, struct pipe_arg *pipes, unsigned int co
 
 		if (bo_fb_create(dev->fd, pipes[0].fourcc, dev->mode.width, dev->mode.height,
 			             primary_fill, &dev->mode.bo, &dev->mode.fb_id))
-			return;
+			return 0;
 	}
 
 	for (i = 0; i < count; i++) {
@@ -1636,7 +1698,7 @@ static void set_mode(struct device *dev, struct pipe_arg *pipes, unsigned int co
 
 			if (ret) {
 				fprintf(stderr, "failed to set mode: %s\n", strerror(errno));
-				return;
+				return 0;
 			}
 
 			set_gamma(dev, pipe->crtc_id, pipe->fourcc);
@@ -1662,6 +1724,77 @@ static void set_mode(struct device *dev, struct pipe_arg *pipes, unsigned int co
 			}
 		}
 	}
+
+	return count;
+}
+
+static void writeback_config(struct device *dev, struct pipe_arg *pipes, unsigned int count)
+{
+	drmModeConnector *connector;
+	unsigned int i, j;
+
+	for (j = 0; j < count; j++) {
+		struct pipe_arg *pipe = &pipes[j];
+
+		for (i = 0; i < pipe->num_cons; i++) {
+			connector = get_connector_by_id(dev, pipe->con_ids[i]);
+			if (connector->connector_type == DRM_MODE_CONNECTOR_WRITEBACK) {
+				if (!pipe->mode) {
+					fprintf(stderr, "no mode for writeback\n");
+					return;
+				}
+				bo_fb_create(dev->fd, pipes[j].fourcc,
+					     pipe->mode->hdisplay, pipe->mode->vdisplay,
+					     UTIL_PATTERN_PLAIN,
+					     &pipe->out_bo, &pipe->out_fb_id);
+				add_property(dev, pipe->con_ids[i], "WRITEBACK_FB_ID",
+					     pipe->out_fb_id);
+				add_property(dev, pipe->con_ids[i], "WRITEBACK_OUT_FENCE_PTR",
+					     (uintptr_t)(&dev->writeback_fence_fd));
+			}
+		}
+	}
+}
+
+static int poll_writeback_fence(int fd, int timeout)
+{
+	struct pollfd fds = { fd, POLLIN };
+	int ret;
+
+	do {
+		ret = poll(&fds, 1, timeout);
+		if (ret > 0) {
+			if (fds.revents & (POLLERR | POLLNVAL))
+				return -EINVAL;
+
+			return 0;
+		} else if (ret == 0) {
+			return -ETIMEDOUT;
+		} else {
+			ret = -errno;
+			if (ret == -EINTR || ret == -EAGAIN)
+				continue;
+			return ret;
+		}
+	} while (1);
+
+}
+
+static void dump_output_fb(struct device *dev, struct pipe_arg *pipes, char *dump_path,
+			   unsigned int count)
+{
+	drmModeConnector *connector;
+	unsigned int i, j;
+
+	for (j = 0; j < count; j++) {
+		struct pipe_arg *pipe = &pipes[j];
+
+		for (i = 0; i < pipe->num_cons; i++) {
+			connector = get_connector_by_id(dev, pipe->con_ids[i]);
+			if (connector->connector_type == DRM_MODE_CONNECTOR_WRITEBACK)
+				bo_dump(pipe->out_bo, dump_path);
+		}
+	}
 }
 
 static void atomic_clear_mode(struct device *dev, struct pipe_arg *pipes, unsigned int count)
@@ -1899,8 +2032,9 @@ static int parse_connector(struct pipe_arg *pipe, const char *arg)
 	}
 
 	if (*p == '@') {
-		strncpy(pipe->format_str, p + 1, 4);
-		pipe->format_str[4] = '\0';
+		len = sizeof(pipe->format_str) - 1;
+		strncpy(pipe->format_str, p + 1, len);
+		pipe->format_str[len] = '\0';
 	}
 
 	pipe->fourcc = util_format_fourcc(pipe->format_str);
@@ -1914,6 +2048,7 @@ static int parse_connector(struct pipe_arg *pipe, const char *arg)
 
 static int parse_plane(struct plane_arg *plane, const char *p)
 {
+	unsigned int len;
 	char *end;
 
 	plane->plane_id = strtoul(p, &end, 10);
@@ -1952,8 +2087,9 @@ static int parse_plane(struct plane_arg *plane, const char *p)
 	}
 
 	if (*end == '@') {
-		strncpy(plane->format_str, end + 1, 4);
-		plane->format_str[4] = '\0';
+		len = sizeof(plane->format_str) - 1;
+		strncpy(plane->format_str, end + 1, len);
+		plane->format_str[len] = '\0';
 	} else {
 		strcpy(plane->format_str, "XR24");
 	}
@@ -1992,7 +2128,7 @@ static void parse_fill_patterns(char *arg)
 
 static void usage(char *name)
 {
-	fprintf(stderr, "usage: %s [-acDdefMPpsCvrw]\n", name);
+	fprintf(stderr, "usage: %s [-acDdefMoPpsCvrw]\n", name);
 
 	fprintf(stderr, "\n Query options:\n\n");
 	fprintf(stderr, "\t-c\tlist connectors\n");
@@ -2001,14 +2137,19 @@ static void usage(char *name)
 	fprintf(stderr, "\t-p\tlist CRTCs and planes (pipes)\n");
 
 	fprintf(stderr, "\n Test options:\n\n");
-	fprintf(stderr, "\t-P <plane_id>@<crtc_id>:<w>x<h>[+<x>+<y>][*<scale>][@<format>]\tset a plane\n");
-	fprintf(stderr, "\t-s <connector_id>[,<connector_id>][@<crtc_id>]:[#<mode index>]<mode>[-<vrefresh>][@<format>]\tset a mode\n");
+	fprintf(stderr, "\t-P <plane_id>@<crtc_id>:<w>x<h>[+<x>+<y>][*<scale>][@<format>]\tset a plane, see 'plane-topology'\n");
+	fprintf(stderr, "\t-s <connector_id>[,<connector_id>][@<crtc_id>]:mode[@<format>]\tset a mode, see 'mode-topology'\n");
+	fprintf(stderr, "\t\twhere mode can be specified as:\n");
+	fprintf(stderr, "\t\t<hdisp>x<vdisp>[-<vrefresh>]\n");
+	fprintf(stderr, "\t\t<hdisp>,<hss>,<hse>,<htot>,<vdisp>,<vss>,<vse>,<vtot>-<vrefresh>\n");
+	fprintf(stderr, "\t\t#<mode index>\n");
 	fprintf(stderr, "\t-C\ttest hw cursor\n");
 	fprintf(stderr, "\t-v\ttest vsynced page flipping\n");
 	fprintf(stderr, "\t-r\tset the preferred mode for all connectors\n");
-	fprintf(stderr, "\t-w <obj_id>:<prop_name>:<value>\tset property\n");
+	fprintf(stderr, "\t-w <obj_id>:<prop_name>:<value>\tset property, see 'property'\n");
 	fprintf(stderr, "\t-a \tuse atomic API\n");
 	fprintf(stderr, "\t-F pattern1,pattern2\tspecify fill patterns\n");
+	fprintf(stderr, "\t-o <desired file path> \t Dump writeback output buffer to file\n");
 
 	fprintf(stderr, "\n Generic options:\n\n");
 	fprintf(stderr, "\t-d\tdrop master after mode set\n");
@@ -2016,10 +2157,29 @@ static void usage(char *name)
 	fprintf(stderr, "\t-D device\tuse the given device\n");
 
 	fprintf(stderr, "\n\tDefault is to dump all info.\n");
+
+	fprintf(stderr, "\n");
+	fprintf(stderr, "Plane Topology is defined as:\n");
+	fprintf(stderr, "\tplane-topology\t::= plane-id '@' crtc-id ':' width 'x' height ( <plane-offsets> )? ;\n");
+	fprintf(stderr, "\tplane-offsets\t::= '+' x-offset '+' y-offset ( <plane-scale> )? ;\n");
+	fprintf(stderr, "\tplane-scale\t::= '*' scale ( <plane-format> )? ;\n");
+	fprintf(stderr, "\tplane-format\t::= '@' format ;\n");
+
+	fprintf(stderr, "\n");
+	fprintf(stderr, "Mode Topology is defined as:\n");
+	fprintf(stderr, "\tmode-topology\t::= connector-id ( ',' connector-id )* ( '@' crtc-id )? ':' <mode-selection> ( '@' format )? ;\n");
+	fprintf(stderr, "\tmode-selection\t::=  <indexed-mode> | <named-mode> | <custom-mode> ;\n");
+	fprintf(stderr, "\tindexed-mode\t::=  '#' mode-index ;\n");
+	fprintf(stderr, "\tnamed-mode\t::=  width 'x' height ( '-' vrefresh )? ;\n");
+	fprintf(stderr, "\tcustom-mode\t::=  hdisplay ',' hsyncstart ',' hsyncend ',' htotal ',' vdisplay ',' vsyncstart ',' vsyncend ',' vtotal '-' vrefresh ;\n");
+
+	fprintf(stderr, "\n");
+	fprintf(stderr, "Property is defined as:\n");
+	fprintf(stderr, "\tproperty\t::= object-id ':' property-name ':' value ;\n");
 	exit(0);
 }
 
-static char optstr[] = "acdD:efF:M:P:ps:Cvrw:";
+static char optstr[] = "acdD:efF:M:P:ps:Cvrw:o:";
 
 int main(int argc, char **argv)
 {
@@ -2042,6 +2202,7 @@ int main(int argc, char **argv)
 	struct property_arg *prop_args = NULL;
 	unsigned int args = 0;
 	int ret;
+	char *dump_path = NULL;
 
 	memset(&dev, 0, sizeof dev);
 
@@ -2080,6 +2241,9 @@ int main(int argc, char **argv)
 			/* Preserve the default behaviour of dumping all information. */
 			args--;
 			break;
+		case 'o':
+			dump_path = optarg;
+			break;
 		case 'P':
 			plane_args = realloc(plane_args,
 					     (plane_count + 1) * sizeof *plane_args);
@@ -2145,8 +2309,8 @@ int main(int argc, char **argv)
 	if (!args)
 		encoders = connectors = crtcs = planes = framebuffers = 1;
 
-	if (test_vsync && !count) {
-		fprintf(stderr, "page flipping requires at least one -s option.\n");
+	if (test_vsync && !count && !set_preferred) {
+		fprintf(stderr, "page flipping requires at least one -s or -r option.\n");
 		return -1;
 	}
 	if (set_preferred && count) {
@@ -2154,17 +2318,13 @@ int main(int argc, char **argv)
 		return -1;
 	}
 
-	if (set_preferred && plane_count) {
-		fprintf(stderr, "cannot use -r (preferred) when -P (plane) is set\n");
-		return -1;
-	}
-
 	dev.fd = util_open(device, module);
 	if (dev.fd < 0)
 		return -1;
 
 	if (use_atomic) {
 		ret = drmSetClientCap(dev.fd, DRM_CLIENT_CAP_ATOMIC, 1);
+		drmSetClientCap(dev.fd, DRM_CLIENT_CAP_WRITEBACK_CONNECTORS, 1);
 		if (ret) {
 			fprintf(stderr, "no atomic modesetting support: %s\n", strerror(errno));
 			drmClose(dev.fd);
@@ -2188,12 +2348,13 @@ int main(int argc, char **argv)
 	dump_resource(&dev, planes);
 	dump_resource(&dev, framebuffers);
 
+	if (dev.use_atomic)
+		dev.req = drmModeAtomicAlloc();
+
 	for (i = 0; i < prop_count; ++i)
 		set_property(&dev, &prop_args[i]);
 
 	if (dev.use_atomic) {
-		dev.req = drmModeAtomicAlloc();
-
 		if (set_preferred || (count && plane_count)) {
 			uint64_t cap = 0;
 
@@ -2204,7 +2365,16 @@ int main(int argc, char **argv)
 			}
 
 			if (set_preferred || count)
-				set_mode(&dev, pipe_args, count);
+				count = set_mode(&dev, &pipe_args, count);
+
+			if (dump_path) {
+				if (!pipe_has_writeback_connector(&dev, pipe_args, count)) {
+					fprintf(stderr, "No writeback connector found, can not dump.\n");
+					return 1;
+				}
+
+				writeback_config(&dev, pipe_args, count);
+			}
 
 			if (plane_count)
 				atomic_set_planes(&dev, plane_args, plane_count, false);
@@ -2215,6 +2385,18 @@ int main(int argc, char **argv)
 				return 1;
 			}
 
+			/*
+			 * Since only writeback connectors have an output fb, this should only be
+			 * called for writeback.
+			 */
+			if (dump_path) {
+				ret = poll_writeback_fence(dev.writeback_fence_fd, 1000);
+				if (ret)
+					fprintf(stderr, "Poll for writeback error: %d. Skipping Dump.\n",
+							ret);
+				dump_output_fb(&dev, pipe_args, dump_path, count);
+			}
+
 			if (test_vsync)
 				atomic_test_page_flip(&dev, pipe_args, plane_args, plane_count);
 
@@ -2232,17 +2414,22 @@ int main(int argc, char **argv)
 
 			if (count)
 				atomic_clear_mode(&dev, pipe_args, count);
+		}
 
-			ret = drmModeAtomicCommit(dev.fd, dev.req, DRM_MODE_ATOMIC_ALLOW_MODESET, NULL);
-			if (ret)
-				fprintf(stderr, "Atomic Commit failed\n");
+		ret = drmModeAtomicCommit(dev.fd, dev.req, DRM_MODE_ATOMIC_ALLOW_MODESET, NULL);
+		if (ret)
+			fprintf(stderr, "Atomic Commit failed\n");
 
-			if (plane_count)
-				atomic_clear_FB(&dev, plane_args, plane_count);
-		}
+		if (count && plane_count)
+			atomic_clear_FB(&dev, plane_args, plane_count);
 
 		drmModeAtomicFree(dev.req);
 	} else {
+		if (dump_path) {
+			fprintf(stderr, "writeback / dump is only supported in atomic mode\n");
+			return 1;
+		}
+
 		if (set_preferred || count || plane_count) {
 			uint64_t cap = 0;
 
@@ -2253,7 +2440,7 @@ int main(int argc, char **argv)
 			}
 
 			if (set_preferred || count)
-				set_mode(&dev, pipe_args, count);
+				count = set_mode(&dev, &pipe_args, count);
 
 			if (plane_count)
 				set_planes(&dev, plane_args, plane_count);
diff --git a/tests/proptest/Android.bp b/tests/proptest/Android.bp
index e13d060b..f6315565 100644
--- a/tests/proptest/Android.bp
+++ b/tests/proptest/Android.bp
@@ -7,7 +7,7 @@ package {
     default_applicable_licenses: ["external_libdrm_license"],
 }
 
-cc_test {
+cc_binary {
     name: "proptest",
     defaults: ["libdrm_defaults"],
     srcs: ["proptest.c"],
diff --git a/tests/proptest/Makefile.sources b/tests/proptest/Makefile.sources
deleted file mode 100644
index 446110d6..00000000
--- a/tests/proptest/Makefile.sources
+++ /dev/null
@@ -1,2 +0,0 @@
-PROPTEST_FILES := \
-	proptest.c
diff --git a/tests/proptest/proptest.c b/tests/proptest/proptest.c
index 0ab0907d..97cb01fa 100644
--- a/tests/proptest/proptest.c
+++ b/tests/proptest/proptest.c
@@ -127,7 +127,7 @@ dump_prop(uint32_t prop_id, uint64_t value)
 		printf("\t\tenums:");
 		for (i = 0; i < prop->count_enums; i++)
 			printf(" %s=%"PRIu64, prop->enums[i].name,
-			       prop->enums[i].value);
+			       (uint64_t)prop->enums[i].value);
 		printf("\n");
 	} else if (drm_property_type_is(prop, DRM_MODE_PROP_BITMASK)) {
 		printf("\t\tvalues:");
@@ -192,7 +192,7 @@ static void listConnectorProperties(void)
 		}
 
 		printf("Connector %u (%s-%u)\n", c->connector_id,
-		       util_lookup_connector_type_name(c->connector_type),
+		       drmModeGetConnectorTypeName(c->connector_type),
 		       c->connector_type_id);
 
 		listObjectProperties(c->connector_id,
diff --git a/tests/tegra/.gitignore b/tests/tegra/.gitignore
index 5c5216c5..0db9e540 100644
--- a/tests/tegra/.gitignore
+++ b/tests/tegra/.gitignore
@@ -1 +1,2 @@
-openclose
+tegra-gr2d-fill
+tegra-openclose
diff --git a/tests/tegra/drm-test-tegra.c b/tests/tegra/drm-test-tegra.c
new file mode 100644
index 00000000..1a9fa896
--- /dev/null
+++ b/tests/tegra/drm-test-tegra.c
@@ -0,0 +1,147 @@
+/*
+ * Copyright © 2014 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifdef HAVE_CONFIG_H
+#  include "config.h"
+#endif
+
+#include <errno.h>
+#include <stdio.h>
+
+#include "drm-test-tegra.h"
+#include "tegra.h"
+
+int drm_tegra_gr2d_open(struct drm_tegra *drm, struct drm_tegra_gr2d **gr2dp)
+{
+    struct drm_tegra_gr2d *gr2d;
+    int err;
+
+    gr2d = calloc(1, sizeof(*gr2d));
+    if (!gr2d)
+        return -ENOMEM;
+
+    gr2d->drm = drm;
+
+    err = drm_tegra_channel_open(drm, DRM_TEGRA_GR2D, &gr2d->channel);
+    if (err < 0) {
+        free(gr2d);
+        return err;
+    }
+
+    *gr2dp = gr2d;
+
+    return 0;
+}
+
+int drm_tegra_gr2d_close(struct drm_tegra_gr2d *gr2d)
+{
+    if (!gr2d)
+        return -EINVAL;
+
+    drm_tegra_channel_close(gr2d->channel);
+    free(gr2d);
+
+    return 0;
+}
+
+int drm_tegra_gr2d_fill(struct drm_tegra_gr2d *gr2d, struct drm_framebuffer *fb,
+                        unsigned int x, unsigned int y, unsigned int width,
+                        unsigned int height, uint32_t color)
+{
+    struct drm_tegra_bo *fbo = fb->data;
+    struct drm_tegra_pushbuf *pushbuf;
+    struct drm_tegra_mapping *map;
+    struct drm_tegra_job *job;
+    uint32_t *ptr;
+    int err;
+
+    err = drm_tegra_job_new(gr2d->channel, &job);
+    if (err < 0)
+        return err;
+
+    err = drm_tegra_channel_map(gr2d->channel, fbo, 0, &map);
+    if (err < 0)
+        return err;
+
+    err = drm_tegra_job_get_pushbuf(job, &pushbuf);
+    if (err < 0)
+        return err;
+
+    err = drm_tegra_pushbuf_begin(pushbuf, 32, &ptr);
+    if (err < 0)
+        return err;
+
+    *ptr++ = HOST1X_OPCODE_SETCL(0, HOST1X_CLASS_GR2D, 0);
+
+    *ptr++ = HOST1X_OPCODE_MASK(0x9, 0x9);
+    *ptr++ = 0x0000003a;
+    *ptr++ = 0x00000000;
+
+    *ptr++ = HOST1X_OPCODE_MASK(0x1e, 0x7);
+    *ptr++ = 0x00000000;
+    *ptr++ = (2 << 16) | (1 << 6) | (1 << 2);
+    *ptr++ = 0x000000cc;
+
+    *ptr++ = HOST1X_OPCODE_MASK(0x2b, 0x9);
+
+    /* relocate destination buffer */
+    err = drm_tegra_pushbuf_relocate(pushbuf, &ptr, map, 0, 0, 0);
+    if (err < 0) {
+        fprintf(stderr, "failed to relocate buffer object: %d\n", err);
+        return err;
+    }
+
+    *ptr++ = fb->pitch;
+
+    *ptr++ = HOST1X_OPCODE_NONINCR(0x35, 1);
+    *ptr++ = color;
+
+    *ptr++ = HOST1X_OPCODE_NONINCR(0x46, 1);
+    *ptr++ = 0x00000000;
+
+    *ptr++ = HOST1X_OPCODE_MASK(0x38, 0x5);
+    *ptr++ = height << 16 | width;
+    *ptr++ = y << 16 | x;
+
+    err = drm_tegra_pushbuf_end(pushbuf, ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to update push buffer: %d\n", -err);
+        return err;
+    }
+
+    err = drm_tegra_job_submit(job, NULL);
+    if (err < 0) {
+        fprintf(stderr, "failed to submit job: %d\n", err);
+        return err;
+    }
+
+    err = drm_tegra_job_wait(job, 0);
+    if (err < 0) {
+        fprintf(stderr, "failed to wait for fence: %d\n", err);
+        return err;
+    }
+
+    drm_tegra_channel_unmap(map);
+    drm_tegra_job_free(job);
+
+    return 0;
+}
diff --git a/tests/tegra/drm-test-tegra.h b/tests/tegra/drm-test-tegra.h
new file mode 100644
index 00000000..eefa954c
--- /dev/null
+++ b/tests/tegra/drm-test-tegra.h
@@ -0,0 +1,55 @@
+/*
+ * Copyright © 2014 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifndef TEGRA_DRM_TEST_TEGRA_H
+#define TEGRA_DRM_TEST_TEGRA_H
+
+#include "drm-test.h"
+#include "tegra.h"
+
+#define HOST1X_OPCODE_SETCL(offset, classid, mask) \
+    ((0x0 << 28) | (((offset) & 0xfff) << 16) | (((classid) & 0x3ff) << 6) | ((mask) & 0x3f))
+#define HOST1X_OPCODE_INCR(offset, count) \
+    ((0x1 << 28) | (((offset) & 0xfff) << 16) | ((count) & 0xffff))
+#define HOST1X_OPCODE_NONINCR(offset, count) \
+    ((0x2 << 28) | (((offset) & 0xfff) << 16) | ((count) & 0xffff))
+#define HOST1X_OPCODE_MASK(offset, mask) \
+    ((0x3 << 28) | (((offset) & 0xfff) << 16) | ((mask) & 0xffff))
+#define HOST1X_OPCODE_IMM(offset, data) \
+    ((0x4 << 28) | (((offset) & 0xfff) << 16) | ((data) & 0xffff))
+#define HOST1X_OPCODE_EXTEND(subop, value) \
+    ((0xe << 28) | (((subop) & 0xf) << 24) | ((value) & 0xffffff))
+
+#define HOST1X_CLASS_GR2D 0x51
+
+struct drm_tegra_gr2d {
+    struct drm_tegra *drm;
+    struct drm_tegra_channel *channel;
+};
+
+int drm_tegra_gr2d_open(struct drm_tegra *drm, struct drm_tegra_gr2d **gr2dp);
+int drm_tegra_gr2d_close(struct drm_tegra_gr2d *gr2d);
+int drm_tegra_gr2d_fill(struct drm_tegra_gr2d *gr2d, struct drm_framebuffer *fb,
+                        unsigned int x, unsigned int y, unsigned int width,
+                        unsigned int height, uint32_t color);
+
+#endif
diff --git a/tests/tegra/drm-test.c b/tests/tegra/drm-test.c
new file mode 100644
index 00000000..b1ded9cf
--- /dev/null
+++ b/tests/tegra/drm-test.c
@@ -0,0 +1,248 @@
+/*
+ * Copyright © 2014 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifdef HAVE_CONFIG_H
+#  include "config.h"
+#endif
+
+#include <errno.h>
+#include <fcntl.h>
+#include <stdbool.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <unistd.h>
+
+#include <sys/ioctl.h>
+
+#include "xf86drm.h"
+#include "xf86drmMode.h"
+#include "drm_fourcc.h"
+
+#include "drm-test.h"
+
+static int drm_screen_probe_connector(struct drm_screen *screen,
+                                      drmModeConnectorPtr connector)
+{
+    drmModeEncoderPtr encoder;
+    drmModeCrtcPtr crtc;
+    drmModeFBPtr fb;
+
+    encoder = drmModeGetEncoder(screen->fd, connector->encoder_id);
+    if (!encoder)
+        return -ENODEV;
+
+    crtc = drmModeGetCrtc(screen->fd, encoder->crtc_id);
+    if (!crtc) {
+        drmModeFreeEncoder(encoder);
+        return -ENODEV;
+    }
+
+    screen->old_fb = crtc->buffer_id;
+
+    fb = drmModeGetFB(screen->fd, crtc->buffer_id);
+    if (!fb) {
+        /* TODO: create new framebuffer */
+        drmModeFreeEncoder(encoder);
+        drmModeFreeCrtc(crtc);
+        return -ENOSYS;
+    }
+
+    screen->connector = connector->connector_id;
+    screen->old_fb = crtc->buffer_id;
+    screen->crtc = encoder->crtc_id;
+    /* TODO: check crtc->mode_valid */
+    screen->mode = crtc->mode;
+
+    screen->width = fb->width;
+    screen->height = fb->height;
+    screen->pitch = fb->pitch;
+    screen->depth = fb->depth;
+    screen->bpp = fb->bpp;
+
+    drmModeFreeEncoder(encoder);
+    drmModeFreeCrtc(crtc);
+    drmModeFreeFB(fb);
+
+    return 0;
+}
+
+int drm_screen_open(struct drm_screen **screenp, int fd)
+{
+    drmModeConnectorPtr connector;
+    struct drm_screen *screen;
+    bool found = false;
+    drmModeResPtr res;
+    unsigned int i;
+    int err;
+
+    if (!screenp || fd < 0)
+        return -EINVAL;
+
+    screen = calloc(1, sizeof(*screen));
+    if (!screen)
+        return -ENOMEM;
+
+    screen->format = DRM_FORMAT_XRGB8888;
+    screen->fd = fd;
+
+    res = drmModeGetResources(fd);
+    if (!res) {
+        free(screen);
+        return -ENOMEM;
+    }
+
+    for (i = 0; i < (unsigned int)res->count_connectors; i++) {
+        connector = drmModeGetConnector(fd, res->connectors[i]);
+        if (!connector)
+            continue;
+
+        if (connector->connection != DRM_MODE_CONNECTED) {
+            drmModeFreeConnector(connector);
+            continue;
+        }
+
+        err = drm_screen_probe_connector(screen, connector);
+        if (err < 0) {
+            drmModeFreeConnector(connector);
+            continue;
+        }
+
+        drmModeFreeConnector(connector);
+        found = true;
+        break;
+    }
+
+    drmModeFreeResources(res);
+
+    if (!found) {
+        free(screen);
+        return -ENODEV;
+    }
+
+    *screenp = screen;
+
+    return 0;
+}
+
+int drm_screen_close(struct drm_screen *screen)
+{
+    int err;
+
+    err = drmModeSetCrtc(screen->fd, screen->crtc, screen->old_fb, 0, 0,
+                         &screen->connector, 1, &screen->mode);
+    if (err < 0) {
+        fprintf(stderr, "drmModeSetCrtc() failed: %m\n");
+        return -errno;
+    }
+
+    free(screen);
+
+    return 0;
+}
+
+int drm_framebuffer_new(struct drm_framebuffer **fbp,
+                        struct drm_screen *screen, uint32_t handle,
+                        unsigned int width, unsigned int height,
+                        unsigned int pitch, uint32_t format,
+                        void *data)
+{
+    struct drm_framebuffer *fb;
+    uint32_t handles[4];
+    uint32_t pitches[4];
+    uint32_t offsets[4];
+    int err;
+
+    fb = calloc(1, sizeof(*fb));
+    if (!fb)
+        return -ENOMEM;
+
+    fb->fd = screen->fd;
+    fb->width = width;
+    fb->height = height;
+    fb->pitch = pitch;
+    fb->format = format;
+    fb->data = data;
+
+    handles[0] = handle;
+    pitches[0] = pitch;
+    offsets[0] = 0;
+
+    err = drmModeAddFB2(screen->fd, width, height, format, handles,
+                        pitches, offsets, &fb->handle, 0);
+    if (err < 0)
+        return -errno;
+
+    *fbp = fb;
+
+    return 0;
+}
+
+int drm_framebuffer_free(struct drm_framebuffer *fb)
+{
+    int err;
+
+    err = drmModeRmFB(fb->fd, fb->handle);
+    if (err < 0)
+        return -errno;
+
+    free(fb);
+
+    return 0;
+}
+
+int drm_screen_set_framebuffer(struct drm_screen *screen,
+                               struct drm_framebuffer *fb)
+{
+    int err;
+
+    err = drmModeSetCrtc(screen->fd, screen->crtc, fb->handle, 0, 0,
+                         &screen->connector, 1, &screen->mode);
+    if (err < 0)
+        return -errno;
+
+    return 0;
+}
+
+int drm_open(const char *path)
+{
+    int fd, err;
+
+    fd = open(path, O_RDWR);
+    if (fd < 0)
+        return -errno;
+
+    err = drmSetMaster(fd);
+    if (err < 0) {
+        close(fd);
+        return -errno;
+    }
+
+    return fd;
+}
+
+void drm_close(int fd)
+{
+    drmDropMaster(fd);
+    close(fd);
+}
diff --git a/tests/tegra/drm-test.h b/tests/tegra/drm-test.h
new file mode 100644
index 00000000..f11aed42
--- /dev/null
+++ b/tests/tegra/drm-test.h
@@ -0,0 +1,72 @@
+/*
+ * Copyright © 2014 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifndef TEGRA_DRM_TEST_H
+#define TEGRA_DRM_TEST_H
+
+#include <stdint.h>
+#include <stdlib.h>
+
+#include "xf86drmMode.h"
+
+struct drm_screen {
+    int fd;
+
+    unsigned int width;
+    unsigned int height;
+    unsigned int pitch;
+    unsigned int depth;
+    unsigned int bpp;
+
+    drmModeModeInfo mode;
+    uint32_t connector;
+    uint32_t old_fb;
+    uint32_t format;
+    uint32_t crtc;
+};
+
+struct drm_framebuffer {
+    unsigned int width;
+    unsigned int height;
+    unsigned int pitch;
+    uint32_t format;
+    uint32_t handle;
+    void *data;
+    int fd;
+};
+
+int drm_screen_open(struct drm_screen **screenp, int fd);
+int drm_screen_close(struct drm_screen *screen);
+int drm_screen_set_framebuffer(struct drm_screen *screen,
+                               struct drm_framebuffer *fb);
+
+int drm_framebuffer_new(struct drm_framebuffer **fbp,
+                        struct drm_screen *screen, uint32_t handle,
+                        unsigned int width, unsigned int height,
+                        unsigned int pitch, uint32_t format,
+                        void *data);
+int drm_framebuffer_free(struct drm_framebuffer *fb);
+
+int drm_open(const char *path);
+void drm_close(int fd);
+
+#endif
diff --git a/tests/tegra/gr2d-fill.c b/tests/tegra/gr2d-fill.c
new file mode 100644
index 00000000..d138cc4c
--- /dev/null
+++ b/tests/tegra/gr2d-fill.c
@@ -0,0 +1,146 @@
+/*
+ * Copyright © 2014 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifdef HAVE_CONFIG_H
+#  include "config.h"
+#endif
+
+#include <errno.h>
+#include <fcntl.h>
+#include <stdbool.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <unistd.h>
+
+#include <sys/ioctl.h>
+
+#include "xf86drm.h"
+#include "xf86drmMode.h"
+#include "drm_fourcc.h"
+
+#include "drm-test-tegra.h"
+#include "tegra.h"
+
+int main(int argc, char *argv[])
+{
+    uint32_t format = DRM_FORMAT_XRGB8888;
+    struct drm_tegra_gr2d *gr2d;
+    struct drm_framebuffer *fb;
+    struct drm_screen *screen;
+    unsigned int pitch, size;
+    struct drm_tegra_bo *bo;
+    struct drm_tegra *drm;
+    uint32_t handle;
+    int fd, err;
+    void *ptr;
+
+    fd = drm_open(argv[1]);
+    if (fd < 0) {
+        fprintf(stderr, "failed to open DRM device %s: %s\n", argv[1],
+                strerror(errno));
+        return 1;
+    }
+
+    err = drm_screen_open(&screen, fd);
+    if (err < 0) {
+        fprintf(stderr, "failed to open screen: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_new(fd, &drm);
+    if (err < 0) {
+        fprintf(stderr, "failed to create Tegra DRM context: %s\n",
+                strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_gr2d_open(drm, &gr2d);
+    if (err < 0) {
+        fprintf(stderr, "failed to open gr2d channel: %s\n",
+                strerror(-err));
+        return 1;
+    }
+
+    pitch = screen->width * screen->bpp / 8;
+    size = pitch * screen->height;
+
+    err = drm_tegra_bo_new(drm, 0, size, &bo);
+    if (err < 0) {
+        fprintf(stderr, "failed to create buffer object: %s\n",
+                strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_bo_get_handle(bo, &handle);
+    if (err < 0) {
+        fprintf(stderr, "failed to get handle to buffer object: %s\n",
+                strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_bo_map(bo, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to map buffer object: %s\n",
+                strerror(-err));
+        return 1;
+    }
+
+    memset(ptr, 0xff, size);
+
+    err = drm_framebuffer_new(&fb, screen, handle, screen->width,
+                              screen->height, pitch, format, bo);
+    if (err < 0) {
+        fprintf(stderr, "failed to create framebuffer: %s\n",
+                strerror(-err));
+        return 1;
+    }
+
+    err = drm_screen_set_framebuffer(screen, fb);
+    if (err < 0) {
+        fprintf(stderr, "failed to display framebuffer: %s\n",
+                strerror(-err));
+        return 1;
+    }
+
+    sleep(1);
+
+    err = drm_tegra_gr2d_fill(gr2d, fb, fb->width / 4, fb->height / 4,
+                              fb->width / 2, fb->height / 2, 0x00000000);
+    if (err < 0) {
+        fprintf(stderr, "failed to fill rectangle: %s\n",
+                strerror(-err));
+        return 1;
+    }
+
+    sleep(1);
+
+    drm_framebuffer_free(fb);
+    drm_tegra_bo_unref(bo);
+    drm_tegra_gr2d_close(gr2d);
+    drm_tegra_close(drm);
+    drm_screen_close(screen);
+    drm_close(fd);
+
+    return 0;
+}
diff --git a/tests/tegra/host1x.h b/tests/tegra/host1x.h
new file mode 100644
index 00000000..902b0c12
--- /dev/null
+++ b/tests/tegra/host1x.h
@@ -0,0 +1,34 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifndef HOST1X_H
+#define HOST1X_H
+
+#define HOST1X_OPCODE_SETCL(offset, classid, mask) \
+    ((0x0 << 28) | (((offset) & 0xfff) << 16) | (((classid) & 0x3ff) << 6) | ((mask) & 0x3f))
+
+#define HOST1X_OPCODE_INCR(offset, count) \
+    ((0x1 << 28) | (((offset) & 0xfff) << 16) | ((count) & 0xffff))
+
+#define HOST1X_CLASS_VIC 0x5d
+
+#endif
diff --git a/tests/tegra/meson.build b/tests/tegra/meson.build
index 4f8c54f4..26a32e86 100644
--- a/tests/tegra/meson.build
+++ b/tests/tegra/meson.build
@@ -18,10 +18,94 @@
 # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 # SOFTWARE.
 
+inc_tegra = include_directories('../../tegra')
+
+libdrm_test = static_library(
+  'drm-test',
+  [files('drm-test.c', 'drm-test.h'), config_file ],
+  include_directories : [inc_root, inc_drm, inc_tegra],
+  link_with : libdrm,
+)
+
+libdrm_test_tegra = static_library(
+  'drm-test-tegra',
+  [files(
+    'drm-test-tegra.c',
+    'drm-test-tegra.h',
+    'vic.c',
+    'vic.h',
+    'vic30.c',
+    'vic30.h',
+    'vic40.c',
+    'vic40.h',
+    'vic41.c',
+    'vic41.h',
+    'vic42.c',
+    'vic42.h',
+  ), config_file ],
+  include_directories : [inc_root, inc_drm, inc_tegra],
+  link_with : libdrm,
+)
+
 openclose = executable(
-  'openclose',
+  'tegra-openclose',
   files('openclose.c'),
-  include_directories : [inc_root, inc_drm, include_directories('../../tegra')],
+  include_directories : [inc_root, inc_drm, inc_tegra],
   c_args : libdrm_c_args,
   link_with : [libdrm, libdrm_tegra],
+  install : with_install_tests,
+)
+
+gr2d_fill = executable(
+  'tegra-gr2d-fill',
+  files('gr2d-fill.c'),
+  include_directories : [inc_root, inc_drm, inc_tegra],
+  c_args : libdrm_c_args,
+  link_with : [libdrm, libdrm_tegra, libdrm_test, libdrm_test_tegra],
+  install : with_install_tests,
+)
+
+syncpt_wait = executable(
+  'tegra-syncpt-wait',
+  files('syncpt-wait.c'),
+  include_directories : [inc_root, inc_drm, inc_tegra],
+  c_args : libdrm_c_args,
+  link_with : [libdrm, libdrm_tegra, libdrm_test, libdrm_test_tegra],
+  install : with_install_tests,
+)
+
+syncpt_timeout = executable(
+  'tegra-syncpt-timeout',
+  files('syncpt-timeout.c'),
+  include_directories : [inc_root, inc_drm, inc_tegra],
+  c_args : libdrm_c_args,
+  link_with : [libdrm, libdrm_tegra, libdrm_test, libdrm_test_tegra],
+  install : with_install_tests,
+)
+
+vic_clear = executable(
+  'tegra-vic-clear',
+  files('vic-clear.c'),
+  include_directories : [inc_root, inc_drm, inc_tegra],
+  c_args : libdrm_c_args,
+  link_with : [libdrm, libdrm_tegra, libdrm_test, libdrm_test_tegra],
+  install : with_install_tests,
+)
+
+vic_blit = executable(
+  'tegra-vic-blit',
+  files('vic-blit.c'),
+  include_directories : [inc_root, inc_drm, inc_tegra],
+  c_args : libdrm_c_args,
+  link_with : [libdrm, libdrm_tegra, libdrm_test, libdrm_test_tegra],
+  install : with_install_tests,
+)
+
+vic_flip = executable(
+  'tegra-vic-flip',
+  files('vic-flip.c'),
+  include_directories : [inc_root, inc_drm, inc_tegra],
+  c_args : libdrm_c_args,
+  link_with : [libdrm, libdrm_tegra, libdrm_test, libdrm_test_tegra],
+  install : with_install_tests,
 )
diff --git a/tests/tegra/openclose.c b/tests/tegra/openclose.c
index f80f52d4..61dbc2ba 100644
--- a/tests/tegra/openclose.c
+++ b/tests/tegra/openclose.c
@@ -31,37 +31,37 @@ static const char default_device[] = "/dev/dri/card0";
 
 int main(int argc, char *argv[])
 {
-	struct drm_tegra *tegra;
-	drmVersionPtr version;
-	const char *device;
-	int err, fd;
+    struct drm_tegra *tegra;
+    drmVersionPtr version;
+    const char *device;
+    int err, fd;
 
-	if (argc < 2)
-		device = default_device;
-	else
-		device = argv[1];
+    if (argc < 2)
+        device = default_device;
+    else
+        device = argv[1];
 
-	fd = open(device, O_RDWR);
-	if (fd < 0)
-		return 1;
+    fd = open(device, O_RDWR);
+    if (fd < 0)
+        return 1;
 
-	version = drmGetVersion(fd);
-	if (version) {
-		printf("Version: %d.%d.%d\n", version->version_major,
-		       version->version_minor, version->version_patchlevel);
-		printf("  Name: %s\n", version->name);
-		printf("  Date: %s\n", version->date);
-		printf("  Description: %s\n", version->desc);
+    version = drmGetVersion(fd);
+    if (version) {
+        printf("Version: %d.%d.%d\n", version->version_major,
+               version->version_minor, version->version_patchlevel);
+        printf("  Name: %s\n", version->name);
+        printf("  Date: %s\n", version->date);
+        printf("  Description: %s\n", version->desc);
 
-		drmFreeVersion(version);
-	}
+        drmFreeVersion(version);
+    }
 
-	err = drm_tegra_new(&tegra, fd);
-	if (err < 0)
-		return 1;
+    err = drm_tegra_new(fd, &tegra);
+    if (err < 0)
+        return 1;
 
-	drm_tegra_close(tegra);
-	close(fd);
+    drm_tegra_close(tegra);
+    close(fd);
 
-	return 0;
+    return 0;
 }
diff --git a/tests/tegra/syncpt-timeout.c b/tests/tegra/syncpt-timeout.c
new file mode 100644
index 00000000..fea3665c
--- /dev/null
+++ b/tests/tegra/syncpt-timeout.c
@@ -0,0 +1,163 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#include <errno.h>
+#include <fcntl.h>
+#include <stdio.h>
+#include <string.h>
+#include <unistd.h>
+
+#include "tegra.h"
+
+#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
+
+static int channel_open(struct drm_tegra *drm,
+                        struct drm_tegra_channel **channel)
+{
+    static const struct {
+        enum drm_tegra_class class;
+        const char *name;
+    } classes[] = {
+        { DRM_TEGRA_VIC,  "VIC"  },
+        { DRM_TEGRA_GR2D, "GR2D" },
+    };
+    unsigned int i;
+    int err;
+
+    for (i = 0; i < ARRAY_SIZE(classes); i++) {
+        err = drm_tegra_channel_open(drm, classes[i].class, channel);
+        if (err < 0) {
+            fprintf(stderr, "failed to open channel to %s: %s\n",
+                    classes[i].name, strerror(-err));
+            continue;
+        }
+
+        break;
+    }
+
+    return err;
+}
+
+int main(int argc, char *argv[])
+{
+    const char *device = "/dev/dri/renderD128";
+    struct drm_tegra_syncpoint *syncpt;
+    struct drm_tegra_channel *channel;
+    struct drm_tegra_pushbuf *pushbuf;
+    struct drm_tegra_job *job;
+    struct drm_tegra *drm;
+    uint32_t *ptr;
+    int fd, err;
+
+    if (argc > 1)
+        device = argv[1];
+
+    fd = open(device, O_RDWR);
+    if (fd < 0) {
+        fprintf(stderr, "open() failed: %s\n", strerror(errno));
+        return 1;
+    }
+
+    err = drm_tegra_new(fd, &drm);
+    if (err < 0) {
+        fprintf(stderr, "failed to open Tegra device: %s\n", strerror(-err));
+        close(fd);
+        return 1;
+    }
+
+    err = drm_tegra_syncpoint_new(drm, &syncpt);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate syncpoint: %s\n", strerror(-err));
+        drm_tegra_close(drm);
+        close(fd);
+        return 1;
+    }
+
+    err = channel_open(drm, &channel);
+    if (err < 0) {
+        fprintf(stderr, "failed to open channel: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_new(channel, &job);
+    if (err < 0) {
+        fprintf(stderr, "failed to create job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_get_pushbuf(job, &pushbuf);
+    if (err < 0) {
+        fprintf(stderr, "failed to create push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_begin(pushbuf, 8, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to prepare push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    /*
+     * Empty command streams will be rejected, so we use this as an easy way
+     * to add something to the command stream. But this could be any other,
+     * valid command stream.
+     */
+    err = drm_tegra_pushbuf_sync_cond(pushbuf, &ptr, syncpt,
+                                      DRM_TEGRA_SYNC_COND_IMMEDIATE);
+    if (err < 0) {
+        fprintf(stderr, "failed to push syncpoint: %s\n", strerror(-err));
+        return 1;
+    }
+
+    /* pretend that the syncpoint was incremented a second time */
+    err = drm_tegra_pushbuf_sync(pushbuf, syncpt, 1);
+    if (err < 0) {
+        fprintf(stderr, "failed to push syncpoint: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_end(pushbuf, ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to update push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_submit(job, NULL);
+    if (err < 0) {
+        fprintf(stderr, "failed to submit job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_wait(job, 250000);
+    if (err < 0) {
+        fprintf(stderr, "failed to wait for job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    drm_tegra_job_free(job);
+    drm_tegra_channel_close(channel);
+    drm_tegra_syncpoint_free(syncpt);
+    drm_tegra_close(drm);
+    close(fd);
+
+    return 0;
+}
diff --git a/tests/tegra/syncpt-wait.c b/tests/tegra/syncpt-wait.c
new file mode 100644
index 00000000..f1811742
--- /dev/null
+++ b/tests/tegra/syncpt-wait.c
@@ -0,0 +1,151 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#include <errno.h>
+#include <fcntl.h>
+#include <stdio.h>
+#include <string.h>
+#include <unistd.h>
+
+#include "tegra.h"
+
+#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
+
+static int channel_open(struct drm_tegra *drm,
+                        struct drm_tegra_channel **channel)
+{
+    static const struct {
+        enum drm_tegra_class class;
+        const char *name;
+    } classes[] = {
+        { DRM_TEGRA_VIC,  "VIC"  },
+        { DRM_TEGRA_GR2D, "GR2D" },
+    };
+    unsigned int i;
+    int err;
+
+    for (i = 0; i < ARRAY_SIZE(classes); i++) {
+        err = drm_tegra_channel_open(drm, classes[i].class, channel);
+        if (err < 0) {
+            fprintf(stderr, "failed to open channel to %s: %s\n",
+                    classes[i].name, strerror(-err));
+            continue;
+        }
+
+        break;
+    }
+
+    return err;
+}
+
+int main(int argc, char *argv[])
+{
+    const char *device = "/dev/dri/renderD128";
+    struct drm_tegra_syncpoint *syncpt;
+    struct drm_tegra_channel *channel;
+    struct drm_tegra_pushbuf *pushbuf;
+    struct drm_tegra_job *job;
+    struct drm_tegra *drm;
+    uint32_t *ptr;
+    int fd, err;
+
+    if (argc > 1)
+        device = argv[1];
+
+    fd = open(device, O_RDWR);
+    if (fd < 0) {
+        fprintf(stderr, "open() failed: %s\n", strerror(errno));
+        return 1;
+    }
+
+    err = drm_tegra_new(fd, &drm);
+    if (err < 0) {
+        fprintf(stderr, "failed to open Tegra device: %s\n", strerror(-err));
+        close(fd);
+        return 1;
+    }
+
+    err = drm_tegra_syncpoint_new(drm, &syncpt);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate syncpoint: %s\n", strerror(-err));
+        drm_tegra_close(drm);
+        close(fd);
+        return 1;
+    }
+
+    err = channel_open(drm, &channel);
+    if (err < 0) {
+        fprintf(stderr, "failed to open channel: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_new(channel, &job);
+    if (err < 0) {
+        fprintf(stderr, "failed to create job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_get_pushbuf(job, &pushbuf);
+    if (err < 0) {
+        fprintf(stderr, "failed to create push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_begin(pushbuf, 4, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to prepare push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_sync_cond(pushbuf, &ptr, syncpt,
+                                      DRM_TEGRA_SYNC_COND_IMMEDIATE);
+    if (err < 0) {
+        fprintf(stderr, "failed to push syncpoint: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_end(pushbuf, ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to update push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_submit(job, NULL);
+    if (err < 0) {
+        fprintf(stderr, "failed to submit job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_wait(job, 250000000);
+    if (err < 0) {
+        fprintf(stderr, "failed to wait for job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    drm_tegra_job_free(job);
+    drm_tegra_channel_close(channel);
+    drm_tegra_syncpoint_free(syncpt);
+    drm_tegra_close(drm);
+    close(fd);
+
+    return 0;
+}
diff --git a/tests/tegra/vic-blit.c b/tests/tegra/vic-blit.c
new file mode 100644
index 00000000..7baf9e7a
--- /dev/null
+++ b/tests/tegra/vic-blit.c
@@ -0,0 +1,333 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#include <errno.h>
+#include <fcntl.h>
+#include <stdio.h>
+#include <string.h>
+#include <unistd.h>
+
+#include "tegra.h"
+
+#include "host1x.h"
+#include "vic.h"
+
+/* clear output image to red */
+static int clear(struct vic *vic, struct drm_tegra_channel *channel,
+                 struct vic_image *output)
+{
+    struct drm_tegra_pushbuf *pushbuf;
+    struct drm_tegra_job *job;
+    uint32_t *ptr;
+    int err;
+
+    err = drm_tegra_job_new(channel, &job);
+    if (err < 0) {
+        fprintf(stderr, "failed to create job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_get_pushbuf(job, &pushbuf);
+    if (err < 0) {
+        fprintf(stderr, "failed to create push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = vic_clear(vic, output, 1023, 1023, 0, 0);
+    if (err < 0) {
+        fprintf(stderr, "failed to clear surface: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_begin(pushbuf, 32, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to prepare push buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = vic->ops->execute(vic, pushbuf, &ptr, output, NULL, 0);
+    if (err < 0) {
+        fprintf(stderr, "failed to execute operation: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_sync_cond(pushbuf, &ptr, vic->syncpt,
+                                      DRM_TEGRA_SYNC_COND_OP_DONE);
+    if (err < 0) {
+        fprintf(stderr, "failed to push syncpoint: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_end(pushbuf, ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to update push buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_job_submit(job, NULL);
+    if (err < 0) {
+        fprintf(stderr, "failed to submit job: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_job_wait(job, 1000000000);
+    if (err < 0) {
+        fprintf(stderr, "failed to wait for job: %s\n", strerror(-err));
+        return err;
+    }
+
+    drm_tegra_job_free(job);
+
+    return 0;
+}
+
+/* fill bottom half of image to blue */
+static int fill(struct vic *vic, struct drm_tegra_channel *channel,
+                struct vic_image *output)
+{
+    struct drm_tegra_pushbuf *pushbuf;
+    struct drm_tegra_job *job;
+    uint32_t *ptr;
+    int err;
+
+    err = drm_tegra_job_new(channel, &job);
+    if (err < 0) {
+        fprintf(stderr, "failed to create job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_get_pushbuf(job, &pushbuf);
+    if (err < 0) {
+        fprintf(stderr, "failed to create push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_begin(pushbuf, 32, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to prepare push buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = vic->ops->fill(vic, output, 0, output->height / 2, output->width - 1,
+                         output->height -1, 1023, 0, 0, 1023);
+    if (err < 0) {
+        fprintf(stderr, "failed to fill surface: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = vic->ops->execute(vic, pushbuf, &ptr, output, NULL, 0);
+    if (err < 0) {
+        fprintf(stderr, "failed to execute operation: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_sync_cond(pushbuf, &ptr, vic->syncpt,
+                                      DRM_TEGRA_SYNC_COND_OP_DONE);
+    if (err < 0) {
+        fprintf(stderr, "failed to push syncpoint: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_end(pushbuf, ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to update push buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_job_submit(job, NULL);
+    if (err < 0) {
+        fprintf(stderr, "failed to submit job: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_job_wait(job, 1000000000);
+    if (err < 0) {
+        fprintf(stderr, "failed to wait for job: %s\n", strerror(-err));
+        return err;
+    }
+
+    drm_tegra_job_free(job);
+
+    return 0;
+}
+
+/* blit image */
+static int blit(struct vic *vic, struct drm_tegra_channel *channel,
+                struct vic_image *output, struct vic_image *input)
+{
+    struct drm_tegra_pushbuf *pushbuf;
+    struct drm_tegra_job *job;
+    uint32_t *ptr;
+    int err;
+
+    err = drm_tegra_job_new(channel, &job);
+    if (err < 0) {
+        fprintf(stderr, "failed to create job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_get_pushbuf(job, &pushbuf);
+    if (err < 0) {
+        fprintf(stderr, "failed to create push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_begin(pushbuf, 32, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to prepare push buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = vic->ops->blit(vic, output, input);
+    if (err < 0) {
+        fprintf(stderr, "failed to blit surface: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = vic->ops->execute(vic, pushbuf, &ptr, output, &input, 1);
+    if (err < 0) {
+        fprintf(stderr, "failed to execute operation: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_sync_cond(pushbuf, &ptr, vic->syncpt,
+                                      DRM_TEGRA_SYNC_COND_OP_DONE);
+    if (err < 0) {
+        fprintf(stderr, "failed to push syncpoint: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_end(pushbuf, ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to update push buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_job_submit(job, NULL);
+    if (err < 0) {
+        fprintf(stderr, "failed to submit job: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_job_wait(job, 1000000000);
+    if (err < 0) {
+        fprintf(stderr, "failed to wait for job: %s\n", strerror(-err));
+        return err;
+    }
+
+    drm_tegra_job_free(job);
+
+    return 0;
+}
+
+int main(int argc, char *argv[])
+{
+    const unsigned int format = VIC_PIXEL_FORMAT_A8R8G8B8;
+    const unsigned int kind = VIC_BLK_KIND_PITCH;
+    const unsigned int width = 16, height = 16;
+    const char *device = "/dev/dri/renderD128";
+    struct drm_tegra_channel *channel;
+    struct vic_image *input, *output;
+    struct drm_tegra *drm;
+    unsigned int version;
+    struct vic *vic;
+    int fd, err;
+
+    if (argc > 1)
+        device = argv[1];
+
+    fd = open(device, O_RDWR);
+    if (fd < 0) {
+        fprintf(stderr, "open() failed: %s\n", strerror(errno));
+        return 1;
+    }
+
+    err = drm_tegra_new(fd, &drm);
+    if (err < 0) {
+        fprintf(stderr, "failed to open Tegra device: %s\n", strerror(-err));
+        close(fd);
+        return 1;
+    }
+
+    err = drm_tegra_channel_open(drm, DRM_TEGRA_VIC, &channel);
+    if (err < 0) {
+        fprintf(stderr, "failed to open channel to VIC: %s\n", strerror(-err));
+        return 1;
+    }
+
+    version = drm_tegra_channel_get_version(channel);
+    printf("version: %08x\n", version);
+
+    err = vic_new(drm, channel, &vic);
+    if (err < 0) {
+        fprintf(stderr, "failed to create VIC: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = vic_image_new(vic, width, height, format, kind, DRM_TEGRA_CHANNEL_MAP_READ_WRITE,
+                        &input);
+    if (err < 0) {
+        fprintf(stderr, "failed to create input image: %d\n", err);
+        return 1;
+    }
+
+    err = vic_image_new(vic, width, height, format, kind, DRM_TEGRA_CHANNEL_MAP_READ_WRITE,
+                        &output);
+    if (err < 0) {
+        fprintf(stderr, "failed to create output image: %d\n", err);
+        return 1;
+    }
+
+    err = clear(vic, channel, input);
+    if (err < 0) {
+        fprintf(stderr, "failed to clear image: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = fill(vic, channel, input);
+    if (err < 0) {
+        fprintf(stderr, "failed to fill rectangle: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = blit(vic, channel, output, input);
+    if (err < 0) {
+        fprintf(stderr, "failed to blit image: %s\n", strerror(-err));
+        return 1;
+    }
+
+    printf("input: %ux%u\n", input->width, input->height);
+    vic_image_dump(input, stdout);
+
+    printf("output: %ux%u\n", output->width, output->height);
+    vic_image_dump(output, stdout);
+
+    vic_image_free(output);
+    vic_image_free(input);
+
+    vic_free(vic);
+    drm_tegra_channel_close(channel);
+    drm_tegra_close(drm);
+    close(fd);
+
+    return 0;
+}
diff --git a/tests/tegra/vic-clear.c b/tests/tegra/vic-clear.c
new file mode 100644
index 00000000..da72782e
--- /dev/null
+++ b/tests/tegra/vic-clear.c
@@ -0,0 +1,173 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#include <errno.h>
+#include <fcntl.h>
+#include <stdio.h>
+#include <string.h>
+#include <unistd.h>
+
+#include "util_math.h"
+
+#include "tegra.h"
+
+#include "host1x.h"
+#include "vic.h"
+
+#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
+
+int main(int argc, char *argv[])
+{
+    const unsigned int format = VIC_PIXEL_FORMAT_A8R8G8B8;
+    const unsigned int kind = VIC_BLK_KIND_PITCH;
+    const unsigned int width = 16, height = 16;
+    const char *device = "/dev/dri/renderD128";
+    struct drm_tegra_channel *channel;
+    struct drm_tegra_pushbuf *pushbuf;
+    struct drm_tegra_job *job;
+    struct vic_image *output;
+    struct drm_tegra *drm;
+    unsigned int version;
+    struct vic *vic;
+    uint32_t *pb;
+    int fd, err;
+    void *ptr;
+
+    if (argc > 1)
+        device = argv[1];
+
+    fd = open(device, O_RDWR);
+    if (fd < 0) {
+        fprintf(stderr, "open() failed: %s\n", strerror(errno));
+        return 1;
+    }
+
+    err = drm_tegra_new(fd, &drm);
+    if (err < 0) {
+        fprintf(stderr, "failed to open Tegra device: %s\n", strerror(-err));
+        close(fd);
+        return 1;
+    }
+
+    err = drm_tegra_channel_open(drm, DRM_TEGRA_VIC, &channel);
+    if (err < 0) {
+        fprintf(stderr, "failed to open channel to VIC: %s\n", strerror(-err));
+        return 1;
+    }
+
+    version = drm_tegra_channel_get_version(channel);
+    printf("version: %08x\n", version);
+
+    err = vic_new(drm, channel, &vic);
+    if (err < 0) {
+        fprintf(stderr, "failed to create VIC: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = vic_image_new(vic, width, height, format, kind, DRM_TEGRA_CHANNEL_MAP_READ_WRITE,
+                        &output);
+    if (err < 0) {
+        fprintf(stderr, "failed to create output image: %d\n", err);
+        return 1;
+    }
+
+    printf("image: %zu bytes\n", output->size);
+
+    err = drm_tegra_bo_map(output->bo, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to map output image: %d\n", err);
+        return 1;
+    }
+
+    memset(ptr, 0xff, output->size);
+    drm_tegra_bo_unmap(output->bo);
+
+    printf("output: %ux%u\n", output->width, output->height);
+    vic_image_dump(output, stdout);
+
+    err = drm_tegra_job_new(channel, &job);
+    if (err < 0) {
+        fprintf(stderr, "failed to create job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_get_pushbuf(job, &pushbuf);
+    if (err < 0) {
+        fprintf(stderr, "failed to create push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_begin(pushbuf, 32, &pb);
+    if (err < 0) {
+        fprintf(stderr, "failed to prepare push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = vic_clear(vic, output, 1023, 0, 0, 1023);
+    if (err < 0) {
+        fprintf(stderr, "failed to clear surface: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = vic->ops->execute(vic, pushbuf, &pb, output, NULL, 0);
+    if (err < 0) {
+        fprintf(stderr, "failed to execute operation: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_sync_cond(pushbuf, &pb, vic->syncpt,
+                                      DRM_TEGRA_SYNC_COND_OP_DONE);
+    if (err < 0) {
+        fprintf(stderr, "failed to push syncpoint: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_end(pushbuf, pb);
+    if (err < 0) {
+        fprintf(stderr, "failed to update push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_submit(job, NULL);
+    if (err < 0) {
+        fprintf(stderr, "failed to submit job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_wait(job, 1000000000);
+    if (err < 0) {
+        fprintf(stderr, "failed to wait for job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    printf("output: %ux%u\n", output->width, output->height);
+    vic_image_dump(output, stdout);
+
+    drm_tegra_job_free(job);
+    vic_image_free(output);
+    vic_free(vic);
+    drm_tegra_channel_close(channel);
+    drm_tegra_close(drm);
+    close(fd);
+
+    return 0;
+}
diff --git a/tests/tegra/vic-flip.c b/tests/tegra/vic-flip.c
new file mode 100644
index 00000000..e94336be
--- /dev/null
+++ b/tests/tegra/vic-flip.c
@@ -0,0 +1,333 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#include <errno.h>
+#include <fcntl.h>
+#include <stdio.h>
+#include <string.h>
+#include <unistd.h>
+
+#include "tegra.h"
+
+#include "host1x.h"
+#include "vic.h"
+
+/* clear output image to red */
+static int clear(struct vic *vic, struct drm_tegra_channel *channel,
+                 struct vic_image *output)
+{
+    struct drm_tegra_pushbuf *pushbuf;
+    struct drm_tegra_job *job;
+    uint32_t *ptr;
+    int err;
+
+    err = drm_tegra_job_new(channel, &job);
+    if (err < 0) {
+        fprintf(stderr, "failed to create job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_get_pushbuf(job, &pushbuf);
+    if (err < 0) {
+        fprintf(stderr, "failed to create push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_begin(pushbuf, 32, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to prepare push buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = vic_clear(vic, output, 1023, 0, 0, 1023);
+    if (err < 0) {
+        fprintf(stderr, "failed to clear surface: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = vic->ops->execute(vic, pushbuf, &ptr, output, NULL, 0);
+    if (err < 0) {
+        fprintf(stderr, "failed to execute operation: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_sync_cond(pushbuf, &ptr, vic->syncpt,
+                                      DRM_TEGRA_SYNC_COND_OP_DONE);
+    if (err < 0) {
+        fprintf(stderr, "failed to push syncpoint: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_end(pushbuf, ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to update push buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_job_submit(job, NULL);
+    if (err < 0) {
+        fprintf(stderr, "failed to submit job: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_job_wait(job, 1000000000);
+    if (err < 0) {
+        fprintf(stderr, "failed to wait for job: %s\n", strerror(-err));
+        return err;
+    }
+
+    drm_tegra_job_free(job);
+
+    return 0;
+}
+
+/* fill bottom half of image to blue */
+static int fill(struct vic *vic, struct drm_tegra_channel *channel,
+                struct vic_image *output)
+{
+    struct drm_tegra_pushbuf *pushbuf;
+    struct drm_tegra_job *job;
+    uint32_t *ptr;
+    int err;
+
+    err = drm_tegra_job_new(channel, &job);
+    if (err < 0) {
+        fprintf(stderr, "failed to create job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_get_pushbuf(job, &pushbuf);
+    if (err < 0) {
+        fprintf(stderr, "failed to create push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_begin(pushbuf, 32, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to prepare push buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = vic->ops->fill(vic, output, 0, output->height / 2, output->width - 1,
+                         output->height - 1, 0, 0, 1023, 1023);
+    if (err < 0) {
+        fprintf(stderr, "failed ot fill surface: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = vic->ops->execute(vic, pushbuf, &ptr, output, NULL, 0);
+    if (err < 0) {
+        fprintf(stderr, "failed to execute operation: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_sync_cond(pushbuf, &ptr, vic->syncpt,
+                                      DRM_TEGRA_SYNC_COND_OP_DONE);
+    if (err < 0) {
+        fprintf(stderr, "failed to push syncpoint: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_end(pushbuf, ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to update push buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_job_submit(job, NULL);
+    if (err < 0) {
+        fprintf(stderr, "failed to submit job: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_job_wait(job, 1000000000);
+    if (err < 0) {
+        fprintf(stderr, "failed to wait for job: %s\n", strerror(-err));
+        return err;
+    }
+
+    drm_tegra_job_free(job);
+
+    return 0;
+}
+
+/* flip image vertically */
+static int flip(struct vic *vic, struct drm_tegra_channel *channel,
+                struct vic_image *output, struct vic_image *input)
+{
+    struct drm_tegra_pushbuf *pushbuf;
+    struct drm_tegra_job *job;
+    uint32_t *ptr;
+    int err;
+
+    err = drm_tegra_job_new(channel, &job);
+    if (err < 0) {
+        fprintf(stderr, "failed to create job: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_job_get_pushbuf(job, &pushbuf);
+    if (err < 0) {
+        fprintf(stderr, "failed to create push buffer: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = drm_tegra_pushbuf_begin(pushbuf, 32, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to prepare push buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = vic->ops->flip(vic, output, input);
+    if (err < 0) {
+        fprintf(stderr, "failed to flip: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = vic->ops->execute(vic, pushbuf, &ptr, output, &input, 1);
+    if (err < 0) {
+        fprintf(stderr, "failed to execute operation: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_sync_cond(pushbuf, &ptr, vic->syncpt,
+                                      DRM_TEGRA_SYNC_COND_OP_DONE);
+    if (err < 0) {
+        fprintf(stderr, "failed to push syncpoint: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_pushbuf_end(pushbuf, ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to update push buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_job_submit(job, NULL);
+    if (err < 0) {
+        fprintf(stderr, "failed to submit job: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_job_wait(job, 1000000000);
+    if (err < 0) {
+        fprintf(stderr, "failed to wait for job: %s\n", strerror(-err));
+        return err;
+    }
+
+    drm_tegra_job_free(job);
+
+    return 0;
+}
+
+int main(int argc, char *argv[])
+{
+    const unsigned int format = VIC_PIXEL_FORMAT_A8R8G8B8;
+    const unsigned int kind = VIC_BLK_KIND_PITCH;
+    const unsigned int width = 16, height = 16;
+    const char *device = "/dev/dri/renderD128";
+    struct drm_tegra_channel *channel;
+    struct vic_image *input, *output;
+    struct drm_tegra *drm;
+    unsigned int version;
+    struct vic *vic;
+    int fd, err;
+
+    if (argc > 1)
+        device = argv[1];
+
+    fd = open(device, O_RDWR);
+    if (fd < 0) {
+        fprintf(stderr, "open() failed: %s\n", strerror(errno));
+        return 1;
+    }
+
+    err = drm_tegra_new(fd, &drm);
+    if (err < 0) {
+        fprintf(stderr, "failed to open Tegra device: %s\n", strerror(-err));
+        close(fd);
+        return 1;
+    }
+
+    err = drm_tegra_channel_open(drm, DRM_TEGRA_VIC, &channel);
+    if (err < 0) {
+        fprintf(stderr, "failed to open channel to VIC: %s\n", strerror(-err));
+        return 1;
+    }
+
+    version = drm_tegra_channel_get_version(channel);
+    printf("version: %08x\n", version);
+
+    err = vic_new(drm, channel, &vic);
+    if (err < 0) {
+        fprintf(stderr, "failed to create VIC: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = vic_image_new(vic, width, height, format, kind, DRM_TEGRA_CHANNEL_MAP_READ_WRITE,
+                        &input);
+    if (err < 0) {
+        fprintf(stderr, "failed to create input image: %d\n", err);
+        return 1;
+    }
+
+    err = vic_image_new(vic, width, height, format, kind, DRM_TEGRA_CHANNEL_MAP_READ_WRITE,
+                        &output);
+    if (err < 0) {
+        fprintf(stderr, "failed to create output image: %d\n", err);
+        return 1;
+    }
+
+    err = clear(vic, channel, input);
+    if (err < 0) {
+        fprintf(stderr, "failed to clear image: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = fill(vic, channel, input);
+    if (err < 0) {
+        fprintf(stderr, "failed to fill rectangle: %s\n", strerror(-err));
+        return 1;
+    }
+
+    err = flip(vic, channel, output, input);
+    if (err < 0) {
+        fprintf(stderr, "failed to flip image: %s\n", strerror(-err));
+        return 1;
+    }
+
+    printf("input: %ux%u\n", input->width, input->height);
+    vic_image_dump(input, stdout);
+
+    printf("output: %ux%u\n", output->width, output->height);
+    vic_image_dump(output, stdout);
+
+    vic_image_free(output);
+    vic_image_free(input);
+
+    vic_free(vic);
+    drm_tegra_channel_close(channel);
+    drm_tegra_close(drm);
+    close(fd);
+
+    return 0;
+}
diff --git a/tests/tegra/vic.c b/tests/tegra/vic.c
new file mode 100644
index 00000000..4163e184
--- /dev/null
+++ b/tests/tegra/vic.c
@@ -0,0 +1,184 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#include <errno.h>
+#include <stdio.h> /* XXX remove */
+#include <stdlib.h>
+
+#include "util_math.h"
+
+#include "tegra.h"
+#include "host1x.h"
+#include "vic.h"
+
+#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
+
+const struct vic_format_info *vic_format_get_info(unsigned int format)
+{
+    static const struct vic_format_info formats[] = {
+        { .format = VIC_PIXEL_FORMAT_A8R8G8B8, .cpp = 4 },
+    };
+    unsigned int i;
+
+    for (i = 0; i < ARRAY_SIZE(formats); i++) {
+        if (formats[i].format == format)
+            return &formats[i];
+    }
+
+    return 0;
+}
+
+int vic_image_new(struct vic *vic, unsigned int width, unsigned int height,
+                  unsigned int format, unsigned int kind, uint32_t flags,
+                  struct vic_image **imagep)
+{
+    const struct vic_format_info *info = vic_format_get_info(format);
+    struct vic_image *image;
+    int err;
+
+    if (!info)
+        return -EINVAL;
+
+    image = calloc(1, sizeof(*image));
+    if (!image)
+        return -ENOMEM;
+
+    if (kind == VIC_BLK_KIND_PITCH)
+        image->align = 256;
+    else
+        image->align = 256; /* XXX */
+
+    image->width = width;
+    image->stride = ALIGN(width, image->align);
+    image->pitch = image->stride * info->cpp;
+    image->height = height;
+    image->format = format;
+    image->kind = kind;
+
+    image->size = image->pitch * image->height;
+
+    printf("image: %ux%u align: %zu stride: %u pitch: %u size: %zu\n",
+           image->width, image->height, image->align, image->stride,
+           image->pitch, image->size);
+
+    err = drm_tegra_bo_new(vic->drm, 0, image->size, &image->bo);
+    if (err < 0) {
+        free(image);
+        return err;
+    }
+
+    err = drm_tegra_channel_map(vic->channel, image->bo, flags, &image->map);
+    if (err < 0) {
+        drm_tegra_bo_unref(image->bo);
+        free(image);
+        return err;
+    }
+
+    *imagep = image;
+    return 0;
+}
+
+void vic_image_free(struct vic_image *image)
+{
+    if (image) {
+        drm_tegra_channel_unmap(image->map);
+        drm_tegra_bo_unref(image->bo);
+        free(image);
+    }
+}
+
+void vic_image_dump(struct vic_image *image, FILE *fp)
+{
+    unsigned int i, j;
+    void *ptr;
+    int err;
+
+    err = drm_tegra_bo_map(image->bo, &ptr);
+    if (err < 0)
+        return;
+
+    for (j = 0; j < image->height; j++) {
+        uint32_t *pixels = (uint32_t *)((unsigned long)ptr + j * image->pitch);
+
+        printf("   ");
+
+        for (i = 0; i < image->width; i++)
+            printf(" %08x", pixels[i]);
+
+        printf("\n");
+    }
+
+    drm_tegra_bo_unmap(image->bo);
+}
+
+/* from vic30.c */
+int vic30_new(struct drm_tegra *drm, struct drm_tegra_channel *channel,
+              struct vic **vicp);
+
+/* from vic40.c */
+int vic40_new(struct drm_tegra *drm, struct drm_tegra_channel *channel,
+              struct vic **vicp);
+
+/* from vic41.c */
+int vic41_new(struct drm_tegra *drm, struct drm_tegra_channel *channel,
+              struct vic **vicp);
+
+/* from vic42.c */
+int vic42_new(struct drm_tegra *drm, struct drm_tegra_channel *channel,
+              struct vic **vicp);
+
+int vic_new(struct drm_tegra *drm, struct drm_tegra_channel *channel,
+            struct vic **vicp)
+{
+    unsigned int version;
+
+    version = drm_tegra_channel_get_version(channel);
+
+    switch (version) {
+    case 0x40:
+        return vic30_new(drm, channel, vicp);
+
+    case 0x21:
+        return vic40_new(drm, channel, vicp);
+
+    case 0x18:
+        return vic41_new(drm, channel, vicp);
+
+    case 0x19:
+        return vic42_new(drm, channel, vicp);
+    }
+
+    return -ENOTSUP;
+}
+
+void vic_free(struct vic *vic)
+{
+    if (vic)
+        vic->ops->free(vic);
+}
+
+int vic_clear(struct vic *vic, struct vic_image *output, unsigned int alpha,
+              unsigned int red, unsigned int green, unsigned int blue)
+{
+    return vic->ops->fill(vic, output, 0, 0, output->width - 1,
+                          output->height - 1, alpha, red, green, blue);
+}
diff --git a/tests/tegra/vic.h b/tests/tegra/vic.h
new file mode 100644
index 00000000..c2056669
--- /dev/null
+++ b/tests/tegra/vic.h
@@ -0,0 +1,181 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifndef VIC_H
+#define VIC_H
+
+#include <stdio.h>
+
+#include "host1x.h"
+
+#define DXVAHD_FRAME_FORMAT_PROGRESSIVE 0
+#define DXVAHD_FRAME_FORMAT_INTERLACED_TOP_FIELD_FIRST 1
+#define DXVAHD_FRAME_FORMAT_INTERLACED_BOTTOM_FIELD_FIRST 2
+#define DXVAHD_FRAME_FORMAT_TOP_FIELD 3
+#define DXVAHD_FRAME_FORMAT_BOTTOM_FIELD 4
+#define DXVAHD_FRAME_FORMAT_SUBPIC_PROGRESSIVE 5
+#define DXVAHD_FRAME_FORMAT_SUBPIC_INTERLACED_TOP_FIELD_FIRST 6
+#define DXVAHD_FRAME_FORMAT_SUBPIC_INTERLACED_BOTTOM_FIELD_FIRST 7
+#define DXVAHD_FRAME_FORMAT_SUBPIC_TOP_FIELD 8
+#define DXVAHD_FRAME_FORMAT_SUBPIC_BOTTOM_FIELD 9
+#define DXVAHD_FRAME_FORMAT_TOP_FIELD_CHROMA_BOTTOM 10
+#define DXVAHD_FRAME_FORMAT_BOTTOM_FIELD_CHROMA_TOP 11
+#define DXVAHD_FRAME_FORMAT_SUBPIC_TOP_FIELD_CHROMA_BOTTOM 12
+#define DXVAHD_FRAME_FORMAT_SUBPIC_BOTTOM_FIELD_CHROMA_TOP 13
+
+#define DXVAHD_ALPHA_FILL_MODE_OPAQUE 0
+#define DXVAHD_ALPHA_FILL_MODE_BACKGROUND 1
+#define DXVAHD_ALPHA_FILL_MODE_DESTINATION 2
+#define DXVAHD_ALPHA_FILL_MODE_SOURCE_STREAM 3
+#define DXVAHD_ALPHA_FILL_MODE_COMPOSITED 4
+#define DXVAHD_ALPHA_FILL_MODE_SOURCE_ALPHA 5
+
+#define VIC_BLEND_SRCFACTC_K1 0
+#define VIC_BLEND_SRCFACTC_K1_TIMES_DST 1
+#define VIC_BLEND_SRCFACTC_NEG_K1_TIMES_DST 2
+#define VIC_BLEND_SRCFACTC_K1_TIMES_SRC 3
+#define VIC_BLEND_SRCFACTC_ZERO 4
+
+#define VIC_BLEND_DSTFACTC_K1 0
+#define VIC_BLEND_DSTFACTC_K2 1
+#define VIC_BLEND_DSTFACTC_K1_TIMES_DST 2
+#define VIC_BLEND_DSTFACTC_NEG_K1_TIMES_DST 3
+#define VIC_BLEND_DSTFACTC_NEG_K1_TIMES_SRC 4
+#define VIC_BLEND_DSTFACTC_ZERO 5
+#define VIC_BLEND_DSTFACTC_ONE 6
+
+#define VIC_BLEND_SRCFACTA_K1 0
+#define VIC_BLEND_SRCFACTA_K2 1
+#define VIC_BLEND_SRCFACTA_NEG_K1_TIMES_DST 2
+#define VIC_BLEND_SRCFACTA_ZERO 3
+
+#define VIC_BLEND_DSTFACTA_K2 0
+#define VIC_BLEND_DSTFACTA_NEG_K1_TIMES_SRC 1
+#define VIC_BLEND_DSTFACTA_ZERO 2
+#define VIC_BLEND_DSTFACTA_ONE 3
+
+#define VIC_BLK_KIND_PITCH 0
+#define VIC_BLK_KIND_GENERIC_16Bx2 1
+
+#define VIC_PIXEL_FORMAT_L8 1
+#define VIC_PIXEL_FORMAT_R8 4
+#define VIC_PIXEL_FORMAT_A8R8G8B8 32
+#define VIC_PIXEL_FORMAT_R8G8B8A8 34
+#define VIC_PIXEL_FORMAT_Y8_U8V8_N420 67
+#define VIC_PIXEL_FORMAT_Y8_V8U8_N420 68
+
+#define VIC_CACHE_WIDTH_16Bx16 0 /* BL16Bx2 */
+#define VIC_CACHE_WIDTH_32Bx8 1 /* BL16Bx2 */
+#define VIC_CACHE_WIDTH_64Bx4 2 /* BL16Bx2, PL */
+#define VIC_CACHE_WIDTH_128Bx2 3 /* BL16Bx2, PL */
+#define VIC_CACHE_WIDTH_256Bx1 4 /* PL */
+
+struct vic_format_info {
+    unsigned int format;
+    unsigned int cpp;
+};
+
+
+#define VIC_UCLASS_INCR_SYNCPT 0x00
+#define VIC_UCLASS_METHOD_OFFSET 0x10
+#define VIC_UCLASS_METHOD_DATA 0x11
+
+static inline void VIC_PUSH_METHOD(struct drm_tegra_pushbuf *pushbuf,
+                                   uint32_t **ptrp, uint32_t method,
+                                   uint32_t value)
+{
+    *(*ptrp)++ = HOST1X_OPCODE_INCR(VIC_UCLASS_METHOD_OFFSET, 2);
+    *(*ptrp)++ = method >> 2;
+    *(*ptrp)++ = value;
+}
+
+static inline void VIC_PUSH_BUFFER(struct drm_tegra_pushbuf *pushbuf,
+                                   uint32_t **ptrp, uint32_t method,
+                                   struct drm_tegra_mapping *map,
+                                   unsigned long offset, unsigned long flags)
+{
+    *(*ptrp)++ = HOST1X_OPCODE_INCR(VIC_UCLASS_METHOD_OFFSET, 2);
+    *(*ptrp)++ = method >> 2;
+
+    drm_tegra_pushbuf_relocate(pushbuf, ptrp, map, offset, 8, flags);
+}
+
+struct vic_image;
+struct vic;
+
+struct vic_ops {
+    int (*fill)(struct vic *vic, struct vic_image *output,
+                unsigned int left, unsigned int top,
+                unsigned int right, unsigned int bottom,
+                unsigned int alpha, unsigned red,
+                unsigned int green, unsigned int blue);
+    int (*blit)(struct vic *vic, struct vic_image *output,
+                struct vic_image *input);
+    int (*flip)(struct vic *vic, struct vic_image *output,
+                struct vic_image *input);
+    int (*execute)(struct vic *vic,
+                   struct drm_tegra_pushbuf *pushbuf,
+                   uint32_t **ptrp,
+                   struct vic_image *output,
+                   struct vic_image **inputs,
+                   unsigned int num_inputs);
+    void (*free)(struct vic *vic);
+};
+
+struct vic {
+    struct drm_tegra *drm;
+    struct drm_tegra_channel *channel;
+    struct drm_tegra_syncpoint *syncpt;
+    const struct vic_ops *ops;
+    unsigned int version;
+};
+
+int vic_new(struct drm_tegra *drm, struct drm_tegra_channel *channel,
+            struct vic **vicp);
+void vic_free(struct vic *vic);
+
+int vic_clear(struct vic *vic, struct vic_image *output, unsigned int alpha,
+              unsigned int red, unsigned int green, unsigned int blue);
+
+struct vic_image {
+    struct drm_tegra_bo *bo;
+    struct drm_tegra_mapping *map;
+    unsigned int width;
+    unsigned int stride;
+    unsigned int pitch;
+    unsigned int height;
+    unsigned int format;
+    unsigned int kind;
+
+    size_t align;
+    size_t size;
+};
+
+const struct vic_format_info *vic_format_get_info(unsigned int format);
+
+int vic_image_new(struct vic *vic, unsigned int width, unsigned int height,
+                  unsigned int format, unsigned int kind, uint32_t flags,
+                  struct vic_image **imagep);
+void vic_image_free(struct vic_image *image);
+void vic_image_dump(struct vic_image *image, FILE *fp);
+
+#endif
diff --git a/tests/tegra/vic30.c b/tests/tegra/vic30.c
new file mode 100644
index 00000000..1bea6e70
--- /dev/null
+++ b/tests/tegra/vic30.c
@@ -0,0 +1,458 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#include <errno.h>
+#include <string.h>
+
+#include "private.h"
+#include "tegra.h"
+#include "vic.h"
+#include "vic30.h"
+
+struct vic30 {
+    struct vic base;
+
+    struct {
+        struct drm_tegra_mapping *map;
+        struct drm_tegra_bo *bo;
+    } config;
+
+    struct {
+        struct drm_tegra_mapping *map;
+        struct drm_tegra_bo *bo;
+    } filter;
+
+    struct {
+        struct drm_tegra_mapping *map;
+        struct drm_tegra_bo *bo;
+    } hist;
+};
+
+static int vic30_fill(struct vic *v, struct vic_image *output,
+                      unsigned int left, unsigned int top,
+                      unsigned int right, unsigned int bottom,
+                      unsigned int alpha, unsigned int red,
+                      unsigned int green, unsigned int blue)
+{
+    struct vic30 *vic = container_of(v, struct vic30, base);
+    ConfigStruct *c;
+    int err;
+
+    err = drm_tegra_bo_map(vic->config.bo, (void **)&c);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    memset(c, 0, sizeof(*c));
+
+    c->surfaceList0Struct.TargetRectLeft = left;
+    c->surfaceList0Struct.TargetRectTop = top;
+    c->surfaceList0Struct.TargetRectRight = right;
+    c->surfaceList0Struct.TargetRectBottom = bottom;
+
+    c->blending0Struct.PixelFormat = output->format;
+    c->blending0Struct.BackgroundAlpha = alpha;
+    c->blending0Struct.BackgroundR = red;
+    c->blending0Struct.BackgroundG = green;
+    c->blending0Struct.BackgroundB = blue;
+    c->blending0Struct.LumaWidth = output->stride - 1;
+    c->blending0Struct.LumaHeight = output->height - 1;
+    c->blending0Struct.ChromaWidth = 16383;
+    c->blending0Struct.ChromaWidth = 16383;
+    c->blending0Struct.TargetRectLeft = left;
+    c->blending0Struct.TargetRectTop = top;
+    c->blending0Struct.TargetRectRight = right;
+    c->blending0Struct.TargetRectBottom = bottom;
+    c->blending0Struct.SurfaceWidth = output->width - 1;
+    c->blending0Struct.SurfaceHeight = output->height - 1;
+    c->blending0Struct.BlkKind = output->kind;
+    c->blending0Struct.BlkHeight = 0;
+
+    c->fetchControl0Struct.TargetRectLeft = left;
+    c->fetchControl0Struct.TargetRectTop = top;
+    c->fetchControl0Struct.TargetRectRight = right;
+    c->fetchControl0Struct.TargetRectBottom = bottom;
+
+    drm_tegra_bo_unmap(vic->config.bo);
+
+    return 0;
+}
+
+static int vic30_blit(struct vic *v, struct vic_image *output,
+                      struct vic_image *input)
+{
+    struct vic30 *vic = container_of(v, struct vic30, base);
+    ColorConversionLumaAlphaStruct *ccla;
+    ColorConversionMatrixStruct *ccm;
+    ColorConversionClampStruct *ccc;
+    SurfaceListSurfaceStruct *s;
+    BlendingSurfaceStruct *b;
+    SurfaceCache0Struct *sc;
+    ConfigStruct *c;
+    int err;
+
+    err = drm_tegra_bo_map(vic->config.bo, (void **)&c);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    memset(c, 0, sizeof(*c));
+
+    c->surfaceList0Struct.TargetRectLeft = 0;
+    c->surfaceList0Struct.TargetRectTop = 0;
+    c->surfaceList0Struct.TargetRectRight = output->width - 1;
+    c->surfaceList0Struct.TargetRectBottom = output->height - 1;
+
+    c->blending0Struct.PixelFormat = output->format;
+    c->blending0Struct.BackgroundAlpha = 0;
+    c->blending0Struct.BackgroundR = 0;
+    c->blending0Struct.BackgroundG = 0;
+    c->blending0Struct.BackgroundB = 0;
+    c->blending0Struct.LumaWidth = output->stride - 1;
+    c->blending0Struct.LumaHeight = output->height - 1;
+    c->blending0Struct.ChromaWidth = 16383;
+    c->blending0Struct.ChromaWidth = 16383;
+    c->blending0Struct.TargetRectLeft = 0;
+    c->blending0Struct.TargetRectTop = 0;
+    c->blending0Struct.TargetRectRight = output->width - 1;
+    c->blending0Struct.TargetRectBottom = output->height - 1;
+    c->blending0Struct.SurfaceWidth = output->width - 1;
+    c->blending0Struct.SurfaceHeight = output->height - 1;
+    c->blending0Struct.BlkKind = output->kind;
+    c->blending0Struct.BlkHeight = 0;
+
+    c->fetchControl0Struct.TargetRectLeft = 0;
+    c->fetchControl0Struct.TargetRectTop = 0;
+    c->fetchControl0Struct.TargetRectRight = output->width - 1;
+    c->fetchControl0Struct.TargetRectBottom = output->height - 1;
+
+    /* setup fetch parameters for slot 0 */
+    c->fetchControl0Struct.Enable0 = 0x1;
+    c->fetchControl0Struct.Iir0 = 0x300;
+
+    /* setup cache parameters for slot 0 */
+    sc = &c->surfaceCache0Struct;
+    sc->PixelFormat0 = input->format;
+
+    /* setup surface configuration for slot 0 */
+    s = &c->surfaceListSurfaceStruct[0];
+    s->Enable = 1;
+    s->FrameFormat = DXVAHD_FRAME_FORMAT_PROGRESSIVE;
+    s->PixelFormat = input->format;
+    s->SurfaceWidth = input->width - 1;
+    s->SurfaceHeight = input->height - 1;
+    s->LumaWidth = input->stride - 1;
+    s->LumaHeight = input->height - 1;
+    s->ChromaWidth = 16383;
+    s->ChromaHeight = 16383;
+    s->CacheWidth = VIC_CACHE_WIDTH_256Bx1; //VIC_CACHE_WIDTH_16Bx16;
+    s->BlkKind = input->kind;
+    s->BlkHeight = 0;
+    s->DestRectLeft = 0;
+    s->DestRectTop = 0;
+    s->DestRectRight = output->width - 1;
+    s->DestRectBottom = output->height - 1;
+    s->SourceRectLeft = 0 << 16;
+    s->SourceRectTop = 0 << 16;
+    s->SourceRectRight = (input->width - 1) << 16;
+    s->SourceRectBottom = (input->height - 1) << 16;
+
+    /* setup color conversion for slot 0 */
+    ccla = &c->colorConversionLumaAlphaStruct[0];
+    ccla->PlanarAlpha = 1023;
+    ccla->ConstantAlpha = 0;
+
+    ccm = &c->colorConversionMatrixStruct[0];
+    ccm->c00 = 1023;
+    ccm->c11 = 1023;
+    ccm->c22 = 1023;
+
+    ccc = &c->colorConversionClampStruct[0];
+    ccc->low = 0;
+    ccc->high = 1023;
+
+    /* setup blending for slot 0 */
+    b = &c->blendingSurfaceStruct[0];
+    b->AlphaK1 = 1023;
+    b->SrcFactCMatchSelect = VIC_BLEND_SRCFACTC_K1;
+    b->SrcFactAMatchSelect = VIC_BLEND_SRCFACTA_K1;
+    b->DstFactCMatchSelect = VIC_BLEND_DSTFACTC_NEG_K1_TIMES_SRC;
+    b->DstFactAMatchSelect = VIC_BLEND_DSTFACTA_NEG_K1_TIMES_SRC;
+
+    drm_tegra_bo_unmap(vic->config.bo);
+
+    return 0;
+}
+
+static int vic30_flip(struct vic *v, struct vic_image *output,
+                      struct vic_image *input)
+{
+    struct vic30 *vic = container_of(v, struct vic30, base);
+    ColorConversionLumaAlphaStruct *ccla;
+    ColorConversionMatrixStruct *ccm;
+    ColorConversionClampStruct *ccc;
+    SurfaceListSurfaceStruct *s;
+    BlendingSurfaceStruct *b;
+    SurfaceCache0Struct *sc;
+    ConfigStruct *c;
+    int err;
+
+    err = drm_tegra_bo_map(vic->config.bo, (void **)&c);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    memset(c, 0, sizeof(*c));
+
+    c->surfaceList0Struct.TargetRectLeft = 0;
+    c->surfaceList0Struct.TargetRectTop = 0;
+    c->surfaceList0Struct.TargetRectRight = output->width - 1;
+    c->surfaceList0Struct.TargetRectBottom = output->height - 1;
+
+    c->blending0Struct.PixelFormat = output->format;
+    c->blending0Struct.BackgroundAlpha = 0;
+    c->blending0Struct.BackgroundR = 0;
+    c->blending0Struct.BackgroundG = 0;
+    c->blending0Struct.BackgroundB = 0;
+    c->blending0Struct.LumaWidth = output->stride - 1;
+    c->blending0Struct.LumaHeight = output->height - 1;
+    c->blending0Struct.ChromaWidth = 16383;
+    c->blending0Struct.ChromaWidth = 16383;
+    c->blending0Struct.TargetRectLeft = 0;
+    c->blending0Struct.TargetRectTop = 0;
+    c->blending0Struct.TargetRectRight = output->width - 1;
+    c->blending0Struct.TargetRectBottom = output->height - 1;
+    c->blending0Struct.SurfaceWidth = output->width - 1;
+    c->blending0Struct.SurfaceHeight = output->height - 1;
+    c->blending0Struct.BlkKind = output->kind;
+    c->blending0Struct.BlkHeight = 0;
+    c->blending0Struct.OutputFlipY = 1;
+
+    c->fetchControl0Struct.TargetRectLeft = 0;
+    c->fetchControl0Struct.TargetRectTop = 0;
+    c->fetchControl0Struct.TargetRectRight = output->width - 1;
+    c->fetchControl0Struct.TargetRectBottom = output->height - 1;
+
+    /* setup fetch parameters for slot 0 */
+    c->fetchControl0Struct.Enable0 = 0x1;
+    c->fetchControl0Struct.Iir0 = 0x300;
+
+    /* setup cache parameters for slot 0 */
+    sc = &c->surfaceCache0Struct;
+    sc->PixelFormat0 = input->format;
+
+    /* setup surface configuration for slot 0 */
+    s = &c->surfaceListSurfaceStruct[0];
+    s->Enable = 1;
+    s->FrameFormat = DXVAHD_FRAME_FORMAT_PROGRESSIVE;
+    s->PixelFormat = input->format;
+    s->SurfaceWidth = input->width - 1;
+    s->SurfaceHeight = input->height - 1;
+    s->LumaWidth = input->stride - 1;
+    s->LumaHeight = input->height - 1;
+    s->ChromaWidth = 16383;
+    s->ChromaHeight = 16383;
+    s->CacheWidth = VIC_CACHE_WIDTH_256Bx1;
+    s->BlkKind = input->kind;
+    s->BlkHeight = 0;
+    s->DestRectLeft = 0;
+    s->DestRectTop = 0;
+    s->DestRectRight = output->width - 1;
+    s->DestRectBottom = output->height - 1;
+    s->SourceRectLeft = 0 << 16;
+    s->SourceRectTop = 0 << 16;
+    s->SourceRectRight = (input->width - 1) << 16;
+    s->SourceRectBottom = (input->height - 1) << 16;
+
+    /* setup color conversion for slot 0 */
+    ccla = &c->colorConversionLumaAlphaStruct[0];
+    ccla->PlanarAlpha = 1023;
+    ccla->ConstantAlpha = 0;
+
+    ccm = &c->colorConversionMatrixStruct[0];
+    ccm->c00 = 1023;
+    ccm->c11 = 1023;
+    ccm->c22 = 1023;
+
+    ccc = &c->colorConversionClampStruct[0];
+    ccc->low = 0;
+    ccc->high = 1023;
+
+    /* setup blending for slot 0 */
+    b = &c->blendingSurfaceStruct[0];
+    b->AlphaK1 = 1023;
+    b->SrcFactCMatchSelect = VIC_BLEND_SRCFACTC_K1;
+    b->SrcFactAMatchSelect = VIC_BLEND_SRCFACTA_K1;
+    b->DstFactCMatchSelect = VIC_BLEND_DSTFACTC_NEG_K1_TIMES_SRC;
+    b->DstFactAMatchSelect = VIC_BLEND_DSTFACTA_NEG_K1_TIMES_SRC;
+
+    drm_tegra_bo_unmap(vic->config.bo);
+
+    return 0;
+}
+
+static int vic30_execute(struct vic *v, struct drm_tegra_pushbuf *pushbuf,
+                         uint32_t **ptrp, struct vic_image *output,
+                         struct vic_image **inputs, unsigned int num_inputs)
+{
+    struct vic30 *vic = container_of(v, struct vic30, base);
+    unsigned int i;
+
+    if (num_inputs > 1)
+        return -EINVAL;
+
+    VIC_PUSH_METHOD(pushbuf, ptrp, NVA0B6_VIDEO_COMPOSITOR_SET_APPLICATION_ID, 1);
+    VIC_PUSH_METHOD(pushbuf, ptrp, NVA0B6_VIDEO_COMPOSITOR_SET_CONTROL_PARAMS, (sizeof(ConfigStruct) / 16) << 16);
+    VIC_PUSH_BUFFER(pushbuf, ptrp, NVA0B6_VIDEO_COMPOSITOR_SET_CONFIG_STRUCT_OFFSET, vic->config.map, 0, 0);
+    VIC_PUSH_BUFFER(pushbuf, ptrp, NVA0B6_VIDEO_COMPOSITOR_SET_HIST_OFFSET, vic->hist.map, 0, 0);
+    VIC_PUSH_BUFFER(pushbuf, ptrp, NVA0B6_VIDEO_COMPOSITOR_SET_OUTPUT_SURFACE_LUMA_OFFSET, output->map, 0, 0);
+
+    for (i = 0; i < num_inputs; i++)
+        VIC_PUSH_BUFFER(pushbuf, ptrp, NVA0B6_VIDEO_COMPOSITOR_SET_SURFACE0_SLOT0_LUMA_OFFSET, inputs[i]->map, 0, 0);
+
+    VIC_PUSH_METHOD(pushbuf, ptrp, NVA0B6_VIDEO_COMPOSITOR_EXECUTE, 1 << 8);
+
+    return 0;
+}
+
+static void vic30_free(struct vic *v)
+{
+    struct vic30 *vic = container_of(v, struct vic30, base);
+
+    drm_tegra_channel_unmap(vic->hist.map);
+    drm_tegra_bo_unref(vic->hist.bo);
+
+    drm_tegra_channel_unmap(vic->filter.map);
+    drm_tegra_bo_unref(vic->filter.bo);
+
+    drm_tegra_channel_unmap(vic->config.map);
+    drm_tegra_bo_unref(vic->config.bo);
+
+    drm_tegra_syncpoint_free(v->syncpt);
+
+    free(vic);
+}
+
+static const struct vic_ops vic30_ops = {
+    .fill = vic30_fill,
+    .blit = vic30_blit,
+    .flip = vic30_flip,
+    .execute = vic30_execute,
+    .free = vic30_free,
+};
+
+int vic30_new(struct drm_tegra *drm, struct drm_tegra_channel *channel,
+              struct vic **vicp)
+{
+    struct vic30 *vic;
+    void *ptr;
+    int err;
+
+    vic = calloc(1, sizeof(*vic));
+    if (!vic)
+        return -ENOMEM;
+
+    vic->base.drm = drm;
+    vic->base.channel = channel;
+    vic->base.ops = &vic30_ops;
+    vic->base.version = 0x40;
+
+    err = drm_tegra_syncpoint_new(drm, &vic->base.syncpt);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate syncpoint: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_new(drm, 0, 16384, &vic->config.bo);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_channel_map(channel, vic->config.bo, DRM_TEGRA_CHANNEL_MAP_READ,
+                                &vic->config.map);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_new(drm, 0, 16384, &vic->filter.bo);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate filter buffer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_map(vic->filter.bo, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to map filter buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    memset(ptr, 0, 16384);
+    drm_tegra_bo_unmap(vic->filter.bo);
+
+    err = drm_tegra_channel_map(channel, vic->filter.bo, DRM_TEGRA_CHANNEL_MAP_READ,
+                                &vic->filter.map);
+    if (err < 0) {
+        fprintf(stderr, "failed to map filter buffer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_new(drm, 0, 4096, &vic->hist.bo);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate history buffer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_map(vic->hist.bo, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to map history buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    memset(ptr, 0, 4096);
+    drm_tegra_bo_unmap(vic->hist.bo);
+
+    err = drm_tegra_channel_map(channel, vic->hist.bo, DRM_TEGRA_CHANNEL_MAP_READ_WRITE,
+                                &vic->hist.map);
+    if (err < 0) {
+        fprintf(stderr, "failed to map histogram buffer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    if (vicp)
+        *vicp = &vic->base;
+
+    return 0;
+}
diff --git a/tests/tegra/vic30.h b/tests/tegra/vic30.h
new file mode 100644
index 00000000..d095c0d2
--- /dev/null
+++ b/tests/tegra/vic30.h
@@ -0,0 +1,439 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifndef VIC30_H
+#define VIC30_H
+
+#include <stdint.h>
+
+#define NVA0B6_VIDEO_COMPOSITOR_SET_APPLICATION_ID 0x200
+#define NVA0B6_VIDEO_COMPOSITOR_EXECUTE 0x300
+#define NVA0B6_VIDEO_COMPOSITOR_EXECUTE_AWAKEN (1 << 8)
+#define NVA0B6_VIDEO_COMPOSITOR_SET_SURFACE0_SLOT0_LUMA_OFFSET 0x400
+#define NVA0B6_VIDEO_COMPOSITOR_SET_SURFACE0_SLOT0_CHROMA_U_OFFSET 0x404
+#define NVA0B6_VIDEO_COMPOSITOR_SET_SURFACE0_SLOT0_CHROMA_V_OFFSET 0x408
+#define NVA0B6_VIDEO_COMPOSITOR_SET_CONTROL_PARAMS 0x700
+#define NVA0B6_VIDEO_COMPOSITOR_SET_CONFIG_STRUCT_OFFSET 0x720
+#define NVA0B6_VIDEO_COMPOSITOR_SET_PALETTE_OFFSET 0x724
+#define NVA0B6_VIDEO_COMPOSITOR_SET_HIST_OFFSET 0x728
+#define NVA0B6_VIDEO_COMPOSITOR_SET_OUTPUT_SURFACE_LUMA_OFFSET 0x730
+#define NVA0B6_VIDEO_COMPOSITOR_SET_OUTPUT_SURFACE_CHROMA_U_OFFSET 0x734
+#define NVA0B6_VIDEO_COMPOSITOR_SET_OUTPUT_SURFACE_CHROMA_V_OFFSET 0x738
+
+#define VIC_PIXEL_FORMAT_L8 1
+#define VIC_PIXEL_FORMAT_R8 4
+#define VIC_PIXEL_FORMAT_A8R8G8B8 32
+#define VIC_PIXEL_FORMAT_R8G8B8A8 34
+#define VIC_PIXEL_FORMAT_Y8_U8V8_N420 67
+#define VIC_PIXEL_FORMAT_Y8_V8U8_N420 68
+
+#define VIC_BLK_KIND_PITCH 0
+#define VIC_BLK_KIND_GENERIC_16Bx2 1
+
+typedef struct {
+    uint64_t DeNoise0 : 1; /* 0 */
+    uint64_t CadenceDetect0 : 1; /* 1 */
+    uint64_t MotionMap0 : 1; /* 2 */
+    uint64_t MedianFilter0 : 1; /* 3 */
+    uint64_t DeNoise1 : 1; /* 4 */
+    uint64_t CadenceDetect1 : 1; /* 5 */
+    uint64_t MotionMap1 : 1; /* 6 */
+    uint64_t MedianFilter1 : 1; /* 7 */
+    uint64_t DeNoise2 : 1; /* 8 */
+    uint64_t CadenceDetect2 : 1; /* 9 */
+    uint64_t MotionMap2 : 1; /* 10 */
+    uint64_t MedianFilter2 : 1; /* 11 */
+    uint64_t DeNoise3 : 1; /* 12 */
+    uint64_t CadenceDetect3 : 1; /* 13 */
+    uint64_t MotionMap3 : 1; /* 14 */
+    uint64_t MedianFilter3 : 1; /* 15 */
+    uint64_t DeNoise4 : 1; /* 16 */
+    uint64_t CadenceDetect4 : 1; /* 17 */
+    uint64_t MotionMap4 : 1; /* 18 */
+    uint64_t MedianFilter4 : 1; /* 19 */
+    uint64_t IsEven0 : 1; /* 20 */
+    uint64_t IsEven1 : 1; /* 21 */
+    uint64_t IsEven2 : 1; /* 22 */
+    uint64_t IsEven3 : 1; /* 23 */
+    uint64_t IsEven4 : 1; /* 24 */
+    uint64_t MMapCombine0 : 1; /* 25 */
+    uint64_t MMapCombine1 : 1; /* 26 */
+    uint64_t MMapCombine2 : 1; /* 27 */
+    uint64_t MMapCombine3 : 1; /* 28 */
+    uint64_t MMapCombine4 : 1; /* 29 */
+    uint64_t reserved0 : 2; /* 31..30 */
+    uint64_t PixelFormat0 : 7; /* 38..32 */
+    uint64_t reserved1 : 1; /* 39 */
+    uint64_t PixelFormat1 : 7; /* 46..40 */
+    uint64_t reserved2 : 1; /* 47 */
+    uint64_t PixelFormat2 : 7; /* 54..48 */
+    uint64_t reserved3 : 1; /* 55 */
+    uint64_t PixelFormat3 : 7; /* 62..56 */
+    uint64_t reserved4 : 1; /* 63 */
+    uint64_t PixelFormat4 : 7; /* 70..64 */
+    uint64_t reserved5 : 1; /* 71 */
+    uint64_t reserved6 : 24; /* 95..72 */
+    uint64_t PPMotion0 : 1; /* 96 */
+    uint64_t PPMotion1 : 1; /* 97 */
+    uint64_t PPMotion2 : 1; /* 98 */
+    uint64_t PPMotion3 : 1; /* 99 */
+    uint64_t PPMotion4 : 1; /* 100 */
+    uint64_t reserved7 : 3; /* 103..101 */
+    uint64_t ChromaEven0 : 1; /* 104 */
+    uint64_t ChromaEven1 : 1; /* 105 */
+    uint64_t ChromaEven2 : 1; /* 106 */
+    uint64_t ChromaEven3 : 1; /* 107 */
+    uint64_t ChromaEven4 : 1; /* 108 */
+    uint64_t reserved8 : 3; /* 111..109 */
+    uint64_t AdvancedDenoise0 : 1; /* 112 */
+    uint64_t AdvancedDenoise1 : 1; /* 113 */
+    uint64_t AdvancedDenoise2 : 1; /* 114 */
+    uint64_t AdvancedDenoise3 : 1; /* 115 */
+    uint64_t AdvancedDenoise4 : 1; /* 116 */
+    uint64_t reserved9 : 3; /* 119..117 */
+    uint64_t reserved10 : 8; /* 127..120 */
+} SurfaceCache0Struct;
+
+typedef struct {
+    uint64_t ClearRectMask0 : 8; /* 7..0 */
+    uint64_t ClearRectMask1 : 8; /* 15..8 */
+    uint64_t ClearRectMask2 : 8; /* 23..16 */
+    uint64_t ClearRectMask3 : 8; /* 31..24 */
+    uint64_t ClearRectMask4 : 8; /* 39..32 */
+    uint64_t reserved0 : 22; /* 61..40 */
+    uint64_t OutputFlipX : 1; /* 62 */
+    uint64_t OutputFlipY : 1; /* 63 */
+    uint64_t TargetRectLeft : 14; /* 77..64 */
+    uint64_t reserved1 : 2; /* 79..78 */
+    uint64_t TargetRectRight : 14; /* 93..80 */
+    uint64_t reserved2 : 2; /* 95..94 */
+    uint64_t TargetRectTop : 14; /* 109..96 */
+    uint64_t reserved3 : 2; /* 111..110 */
+    uint64_t TargetRectBottom : 14; /* 125..112 */
+    uint64_t reserved4 : 2; /* 127..126 */
+} SurfaceList0Struct;
+
+typedef struct {
+    uint64_t ClearRect0Left : 14; /* 13..0 */
+    uint64_t reserved0 : 2; /* 15..14 */
+    uint64_t ClearRect0Right : 14; /* 29..16 */
+    uint64_t reserved1 : 2; /* 31..30 */
+    uint64_t ClearRect0Top : 14; /* 45..32 */
+    uint64_t reserved2 : 2; /* 47..46 */
+    uint64_t ClearRect0Bottom : 14; /* 61..48 */
+    uint64_t reserved3 : 2; /* 63..62 */
+    uint64_t ClearRect1Left : 14; /* 77..64 */
+    uint64_t reserved4 : 2; /* 79..78 */
+    uint64_t ClearRect1Right : 14; /* 93..80 */
+    uint64_t reserved5 : 2; /* 95..94 */
+    uint64_t ClearRect1Top : 14; /* 109..96 */
+    uint64_t reserved6 : 2; /* 111..110 */
+    uint64_t ClearRect1Bottom : 14; /* 125..112 */
+    uint64_t reserved7 : 2; /* 127..126 */
+} SurfaceListClearRectStruct;
+
+typedef struct {
+    uint64_t Enable : 1; /* 0 */
+    uint64_t FrameFormat : 4; /* 4..1 */
+    uint64_t PixelFormat : 7; /* 11..5 */
+    uint64_t reserved0 : 2; /* 13..12 */
+    uint64_t ChromaLocHoriz : 2; /* 15..14 */
+    uint64_t ChromaLocVert : 2; /* 17..16 */
+    uint64_t Panoramic : 12; /* 29..18 */
+    uint64_t reserved1 : 4; /* 33..30 */
+    uint64_t SurfaceWidth : 14; /* 47..34 */
+    uint64_t reserved2 : 1; /* 48 */
+    uint64_t SurfaceHeight : 14; /* 62..49 */
+    uint64_t reserved3 : 1; /* 63 */
+    uint64_t LumaWidth : 14; /* 77..64 */
+    uint64_t reserved4 : 1; /* 78 */
+    uint64_t LumaHeight : 14; /* 92..79 */
+    uint64_t reserved5 : 1; /* 93 */
+    uint64_t ChromaWidth : 14; /* 107..94 */
+    uint64_t reserved6 : 1; /* 108 */
+    uint64_t ChromaHeight : 14; /* 122..109 */
+    uint64_t reserved7 : 1; /* 123 */
+    uint64_t CacheWidth : 3; /* 126..124 */
+    uint64_t reserved8 : 1; /* 127 */
+    /* 128 */
+    uint64_t FilterLengthY : 2; /* 1..0 */
+    uint64_t FilterLengthX : 2; /* 3..2 */
+    uint64_t DetailFltClamp : 6; /* 9..4 */
+    uint64_t reserved9 : 2; /* 11..10 */
+    uint64_t LightLevel : 4; /* 15..12 */
+    uint64_t reserved10 : 4; /* 19..16 */
+    uint64_t reserved11 : 8; /* 27..20 */
+    uint64_t reserved12 : 32; /* 59..28 */
+    uint64_t BlkKind : 4; /* 63..60 */
+    uint64_t DestRectLeft : 14; /* 77..64 */
+    uint64_t reserved13 : 1; /* 78 */
+    uint64_t DestRectRight : 14; /* 92..79 */
+    uint64_t reserved14 : 1; /* 93 */
+    uint64_t DestRectTop : 14; /* 107..94 */
+    uint64_t reserved15 : 1; /* 108 */
+    uint64_t DestRectBottom : 14; /* 122..109 */
+    uint64_t reserved16 : 1; /* 123 */
+    uint64_t BlkHeight : 4; /* 127..124 */
+    /* 256 */
+    uint64_t SourceRectLeft : 30; /* 29..0 */
+    uint64_t reserved17 : 2; /* 31..30 */
+    uint64_t SourceRectRight : 30; /* 61..32 */
+    uint64_t reserved18 : 2; /* 63..62 */
+    uint64_t SourceRectTop : 30; /* 93..64 */
+    uint64_t reserved19 : 2; /* 95..94 */
+    uint64_t SourceRectBottom : 30; /* 125..96 */
+    uint64_t reserved20 : 2; /* 127..126 */
+} SurfaceListSurfaceStruct;
+
+typedef struct {
+    uint64_t l0 : 20; /* 19..0 */
+    uint64_t l1 : 20; /* 39..20 */
+    uint64_t l2 : 20; /* 59..40 */
+    uint64_t r_shift : 4; /* 63..60 */
+    uint64_t l3 : 20; /* 83..64 */
+    uint64_t PlanarAlpha : 10; /* 93..84 */
+    uint64_t ConstantAlpha : 1; /* 94 */
+    uint64_t ClipEnabled : 1; /* 95 */
+    uint64_t LumaKeyLower : 10; /* 105..96 */
+    uint64_t reserved6 : 3; /* 108..106 */
+    uint64_t StereoInterleave : 3; /* 111..109 */
+    uint64_t LumaKeyUpper : 10; /* 121..112 */
+    uint64_t reserved7 : 2; /* 123..122 */
+    uint64_t reserved8 : 1; /* 124 */
+    uint64_t LumaKeyEnabled : 1; /* 125 */
+    uint64_t reserved9 : 2; /* 127..126 */
+} ColorConversionLumaAlphaStruct;
+
+typedef struct {
+    uint64_t c00 : 20; /* 19..0 */
+    uint64_t c10 : 20; /* 39..20 */
+    uint64_t c20 : 20; /* 59..40 */
+    uint64_t r_shift : 4; /* 63..60 */
+    uint64_t c01 : 20; /* 83..64 */
+    uint64_t c11 : 20; /* 103..84 */
+    uint64_t c21 : 20; /* 123..104 */
+    uint64_t reserved0 : 4; /* 127..124 */
+    /* 128 */
+    uint64_t c02 : 20; /* 19..0 */
+    uint64_t c12 : 20; /* 39..20 */
+    uint64_t c22 : 20; /* 59..40 */
+    uint64_t reserved1 : 4; /* 63..60 */
+    uint64_t c03 : 20; /* 83..64 */
+    uint64_t c13 : 20; /* 103..84 */
+    uint64_t c23 : 20; /* 123..104 */
+    uint64_t reserved2 : 4; /* 127..124 */
+} ColorConversionMatrixStruct;
+
+typedef struct {
+    uint64_t low : 10; /* 9..0 */
+    uint64_t reserved0 : 6; /* 15..10 */
+    uint64_t high : 10; /* 25..16 */
+    uint64_t reserved1 : 6; /* 31..26 */
+    uint64_t reserved2 : 32; /* 63..32 */
+    uint64_t reserved3 : 32; /* 95..64 */
+    uint64_t reserved4 : 32; /* 127..96 */
+} ColorConversionClampStruct;
+
+typedef struct {
+    uint64_t PixelFormat : 7; /* 6..0 */
+    uint64_t reserved0 : 1; /* 7 */
+    uint64_t AlphaFillMode : 3; /* 10..8 */
+    uint64_t AlphaFillSlot : 3; /* 13..11 */
+    uint64_t BackgroundAlpha : 10; /* 23..14 */
+    uint64_t BackgroundR : 10; /* 33..24 */
+    uint64_t BackgroundG : 10; /* 43..34 */
+    uint64_t BackgroundB : 10; /* 53..44 */
+    uint64_t ChromaLocHoriz : 2; /* 55..54 */
+    uint64_t ChromaLocVert : 2; /* 57..56 */
+    uint64_t reserved1 : 6; /* 63..58 */
+    uint64_t LumaWidth : 14; /* 77..64 */
+    uint64_t reserved2 : 2; /* 79..78 */
+    uint64_t LumaHeight : 14; /* 93..80 */
+    uint64_t reserved3 : 2; /* 95..94 */
+    uint64_t ChromaWidth : 14; /* 109..96 */
+    uint64_t reserved4 : 2; /* 111..110 */
+    uint64_t ChromaHeight : 14; /* 125..112 */
+    uint64_t reserved5 : 2; /* 127..126 */
+    /* 128 */
+    uint64_t TargetRectLeft : 14; /* 13..0 */
+    uint64_t reserved6 : 2; /* 15..14 */
+    uint64_t TargetRectRight : 14; /* 29..16 */
+    uint64_t reserved7 : 2; /* 31..30 */
+    uint64_t TargetRectTop : 14; /* 45..32 */
+    uint64_t reserved8 : 2; /* 47..46 */
+    uint64_t TargetRectBottom : 14; /* 61..48 */
+    uint64_t reserved9 : 2; /* 63..62 */
+    uint64_t SurfaceWidth : 14; /* 77..64 */
+    uint64_t reserved10 : 2; /* 79..78 */
+    uint64_t SurfaceHeight : 14; /* 93..80 */
+    uint64_t reserved11 : 2; /* 95..94 */
+    uint64_t BlkKind : 4; /* 99..96 */
+    uint64_t BlkHeight : 4; /* 103..100 */
+    uint64_t OutputFlipX : 1; /* 104 */
+    uint64_t OutputFlipY : 1; /* 105 */
+    uint64_t OutputTranspose : 1; /* 106 */
+    uint64_t reserved12 : 21; /* 127..107 */
+} Blending0Struct;
+
+typedef struct {
+    uint64_t AlphaK1 : 10; /* 9..0 */
+    uint64_t reserved0 : 6; /* 15..10 */
+    uint64_t AlphaK2 : 10; /* 25..16 */
+    uint64_t reserved1 : 6; /* 31..26 */
+    uint64_t SrcFactCMatchSelect : 3; /* 34..32 */
+    uint64_t reserved2 : 1; /* 35 */
+    uint64_t DstFactCMatchSelect : 3; /* 38..36 */
+    uint64_t reserved3 : 1; /* 39 */
+    uint64_t SrcFactAMatchSelect : 3; /* 42..40 */
+    uint64_t reserved4 : 1; /* 43 */
+    uint64_t DstFactAMatchSelect : 3; /* 46..44 */
+    uint64_t reserved5 : 1; /* 47 */
+    uint64_t reserved6 : 4; /* 51..48 */
+    uint64_t reserved7 : 4; /* 55..52 */
+    uint64_t reserved8 : 4; /* 59..56 */
+    uint64_t reserved9 : 4; /* 63..60 */
+    uint64_t reserved10 : 2; /* 65..64 */
+    uint64_t OverrideR : 10; /* 75..66 */
+    uint64_t OverrideG : 10; /* 85..76 */
+    uint64_t OverrideB : 10; /* 95..86 */
+    uint64_t OverrideA : 10; /* 105..96 */
+    uint64_t reserved11 : 2; /* 107..106 */
+    uint64_t UseOverrideR : 1; /* 108 */
+    uint64_t UseOverrideG : 1; /* 109 */
+    uint64_t UseOverrideB : 1; /* 110 */
+    uint64_t UseOverrideA : 1; /* 111 */
+    uint64_t MaskR : 1; /* 112 */
+    uint64_t MaskG : 1; /* 113 */
+    uint64_t MaskB : 1; /* 114 */
+    uint64_t MaskA : 1; /* 115 */
+    uint64_t reserved12 : 12; /* 127..116 */
+} BlendingSurfaceStruct;
+
+typedef struct {
+    uint64_t TargetRectLeft : 14; /* 13..0 */
+    uint64_t reserved0 : 2; /* 15..14 */
+    uint64_t TargetRectRight : 14; /* 29..16 */
+    uint64_t reserved1 : 2; /* 31..30 */
+    uint64_t TargetRectTop : 14; /* 45..32 */
+    uint64_t reserved2 : 2; /* 47..46 */
+    uint64_t TargetRectBottom : 14; /* 61..48 */
+    uint64_t reserved3 : 2; /* 63..62 */
+    uint64_t Enable0 : 8; /* 71..64 */
+    uint64_t Enable1 : 8; /* 79..72 */
+    uint64_t Enable2 : 8; /* 87..80 */
+    uint64_t Enable3 : 8; /* 95..88 */
+    uint64_t Enable4 : 8; /* 103..96 */
+    uint64_t DownsampleHoriz : 11; /* 114..104 */
+    uint64_t reserved4 : 1; /* 115 */
+    uint64_t DownsampleVert : 11; /* 126..116 */
+    uint64_t reserved5 : 1; /* 127 */
+    /* 128 */
+    uint64_t FilterNoise0 : 10; /* 9..0 */
+    uint64_t FilterDetail0 : 10; /* 19..10 */
+    uint64_t FilterNoise1 : 10; /* 29..20 */
+    uint64_t reserved6 : 2; /* 31..30 */
+    uint64_t FilterDetail1 : 10; /* 41..32 */
+    uint64_t FilterNoise2 : 10; /* 51..42 */
+    uint64_t FilterDetail2 : 10; /* 61..52 */
+    uint64_t reserved7 : 2; /* 63..62 */
+    uint64_t FilterNoise3 : 10; /* 73..64 */
+    uint64_t FilterDetail3 : 10; /* 83..74 */
+    uint64_t FilterNoise4 : 10; /* 93..84 */
+    uint64_t reserved8 : 2; /* 95..94 */
+    uint64_t FilterDetail4 : 10; /* 105..96 */
+    uint64_t reserved9 : 22; /* 127..106 */
+    /* 256 */
+    uint64_t ChromaNoise0 : 10; /* 9..0 */
+    uint64_t ChromaDetail0 : 10; /* 19..10 */
+    uint64_t ChromaNoise1 : 10; /* 29..20 */
+    uint64_t reserved10 : 2; /* 31..30 */
+    uint64_t ChromaDetail1 : 10; /* 41..32 */
+    uint64_t ChromaNoise2 : 10; /* 51..42 */
+    uint64_t ChromaDetail2 : 10; /* 61..52 */
+    uint64_t reserved11 : 2; /* 63..62 */
+    uint64_t ChromaNoise3 : 10; /* 73..64 */
+    uint64_t ChromaDetail3 : 10; /* 83..74 */
+    uint64_t ChromaNoise4 : 10; /* 93..84 */
+    uint64_t reserved12 : 2; /* 95..94 */
+    uint64_t ChromaDetail4 : 10; /* 105..96 */
+    uint64_t reserved13 : 22; /* 127..106 */
+    /* 384 */
+    uint64_t Mode0 : 4; /* 3..0 */
+    uint64_t AccumWeight0 : 3; /* 6..4 */
+    uint64_t Iir0 : 11; /* 17..7 */
+    uint64_t reserved14 : 2; /* 19..18 */
+    uint64_t Mode1 : 4; /* 23..20 */
+    uint64_t AccumWeight1 : 3; /* 26..24 */
+    uint64_t Iir1 : 11; /* 37..27 */
+    uint64_t reserved15 : 2; /* 39..38 */
+    uint64_t Mode2 : 4; /* 43..40 */
+    uint64_t AccumWeight2 : 3; /* 46..44 */
+    uint64_t Iir2 : 11; /* 57..47 */
+    uint64_t reserved16 : 6; /* 63..58 */
+    uint64_t Mode3 : 4; /* 67..64 */
+    uint64_t AccumWeight3 : 3; /* 70..68 */
+    uint64_t Iir3 : 11; /* 81..71 */
+    uint64_t reserved17 : 2; /* 83..82 */
+    uint64_t Mode4 : 4; /* 87..84 */
+    uint64_t AccumWeight4 : 3; /* 90..88 */
+    uint64_t Iir4 : 11; /* 101..91 */
+    uint64_t reserved18 : 8; /* 109..102 */
+    uint64_t OutputFlipX : 1; /* 110 */
+    uint64_t OutputFlipY : 1; /* 111 */
+    uint64_t reserved19 : 10; /* 121..112 */
+    uint64_t reserved20 : 6; /* 127..122 */
+} FetchControl0Struct;
+
+typedef struct {
+    uint64_t f00 : 10; /* 9..0 */
+    uint64_t f10 : 10; /* 19..10 */
+    uint64_t f20 : 10; /* 29..20 */
+    uint64_t reserved0 : 2; /* 31..30 */
+    uint64_t f01 : 10; /* 41..32 */
+    uint64_t f11 : 10; /* 51..42 */
+    uint64_t f21 : 10; /* 61..52 */
+    uint64_t reserved1 : 2; /* 63..62 */
+    uint64_t f02 : 10; /* 73..64 */
+    uint64_t f12 : 10; /* 83..74 */
+    uint64_t f22 : 10; /* 93..84 */
+    uint64_t reserved2 : 2; /* 95..94 */
+    uint64_t f03 : 10; /* 105..96 */
+    uint64_t f13 : 10; /* 115..106 */
+    uint64_t f23 : 10; /* 125..116 */
+    uint64_t reserved3 : 2; /* 127..126 */
+} FetchControlCoeffStruct;
+
+typedef struct {
+    SurfaceCache0Struct surfaceCache0Struct;
+    SurfaceList0Struct surfaceList0Struct;
+    SurfaceListClearRectStruct surfaceListClearRectStruct[4];
+    SurfaceListSurfaceStruct surfaceListSurfaceStruct[5];
+    ColorConversionLumaAlphaStruct colorConversionLumaAlphaStruct[5];
+    ColorConversionMatrixStruct colorConversionMatrixStruct[5];
+    ColorConversionClampStruct colorConversionClampStruct[5];
+    Blending0Struct blending0Struct;
+    BlendingSurfaceStruct blendingSurfaceStruct[5];
+    FetchControl0Struct fetchControl0Struct;
+    FetchControlCoeffStruct fetchControlCoeffStruct[520];
+} ConfigStruct;
+
+#endif
diff --git a/tests/tegra/vic40.c b/tests/tegra/vic40.c
new file mode 100644
index 00000000..1af09250
--- /dev/null
+++ b/tests/tegra/vic40.c
@@ -0,0 +1,338 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#include <errno.h>
+#include <string.h>
+
+#include "private.h"
+#include "tegra.h"
+#include "vic.h"
+#include "vic40.h"
+
+struct vic40 {
+    struct vic base;
+
+    struct {
+        struct drm_tegra_mapping *map;
+        struct drm_tegra_bo *bo;
+    } config;
+
+    struct {
+        struct drm_tegra_mapping *map;
+        struct drm_tegra_bo *bo;
+    } filter;
+};
+
+static int vic40_fill(struct vic *v, struct vic_image *output,
+                      unsigned int left, unsigned int top,
+                      unsigned int right, unsigned int bottom,
+                      unsigned int alpha, unsigned int red,
+                      unsigned int green, unsigned int blue)
+{
+    struct vic40 *vic = container_of(v, struct vic40, base);
+    ConfigStruct *c;
+    int err;
+
+    err = drm_tegra_bo_map(vic->config.bo, (void **)&c);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    memset(c, 0, sizeof(*c));
+
+    c->outputConfig.TargetRectTop = top;
+    c->outputConfig.TargetRectLeft = left;
+    c->outputConfig.TargetRectRight = right;
+    c->outputConfig.TargetRectBottom = bottom;
+    c->outputConfig.BackgroundAlpha = alpha;
+    c->outputConfig.BackgroundR = red;
+    c->outputConfig.BackgroundG = green;
+    c->outputConfig.BackgroundB = blue;
+
+    c->outputSurfaceConfig.OutPixelFormat = output->format;
+    c->outputSurfaceConfig.OutBlkKind = output->kind;
+    c->outputSurfaceConfig.OutBlkHeight = 0;
+    c->outputSurfaceConfig.OutSurfaceWidth = output->width - 1;
+    c->outputSurfaceConfig.OutSurfaceHeight = output->height - 1;
+    c->outputSurfaceConfig.OutLumaWidth = output->stride - 1;
+    c->outputSurfaceConfig.OutLumaHeight = output->height - 1;
+    c->outputSurfaceConfig.OutChromaWidth = 16383;
+    c->outputSurfaceConfig.OutChromaHeight = 16383;
+
+    drm_tegra_bo_unmap(vic->config.bo);
+
+    return 0;
+}
+
+static int vic40_blit(struct vic *v, struct vic_image *output,
+                      struct vic_image *input)
+{
+    struct vic40 *vic = container_of(v, struct vic40, base);
+    SlotSurfaceConfig *surface;
+    SlotConfig *slot;
+    ConfigStruct *c;
+    int err;
+
+    err = drm_tegra_bo_map(vic->config.bo, (void **)&c);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    memset(c, 0, sizeof(*c));
+
+    c->outputConfig.TargetRectTop = 0;
+    c->outputConfig.TargetRectLeft = 0;
+    c->outputConfig.TargetRectRight = output->width - 1;
+    c->outputConfig.TargetRectBottom = output->height - 1;
+    c->outputConfig.BackgroundAlpha = 1023;
+    c->outputConfig.BackgroundR = 1023;
+    c->outputConfig.BackgroundG = 1023;
+    c->outputConfig.BackgroundB = 1023;
+
+    c->outputSurfaceConfig.OutPixelFormat = output->format;
+    c->outputSurfaceConfig.OutBlkKind = output->kind;
+    c->outputSurfaceConfig.OutBlkHeight = 0;
+    c->outputSurfaceConfig.OutSurfaceWidth = output->width - 1;
+    c->outputSurfaceConfig.OutSurfaceHeight = output->height - 1;
+    c->outputSurfaceConfig.OutLumaWidth = output->stride - 1;
+    c->outputSurfaceConfig.OutLumaHeight = output->height - 1;
+    c->outputSurfaceConfig.OutChromaWidth = 16383;
+    c->outputSurfaceConfig.OutChromaHeight = 16383;
+
+    slot = &c->slotStruct[0].slotConfig;
+    slot->SlotEnable = 1;
+    slot->CurrentFieldEnable = 1;
+    slot->PlanarAlpha = 1023;
+    slot->ConstantAlpha = 1;
+    slot->SourceRectLeft = 0 << 16;
+    slot->SourceRectRight = (input->width - 1) << 16;
+    slot->SourceRectTop = 0 << 16;
+    slot->SourceRectBottom = (input->height - 1) << 16;
+    slot->DestRectLeft = 0;
+    slot->DestRectRight = output->width - 1;
+    slot->DestRectTop = 0;
+    slot->DestRectBottom = output->height - 1;
+    slot->SoftClampHigh = 1023;
+
+    surface = &c->slotStruct[0].slotSurfaceConfig;
+    surface->SlotPixelFormat = input->format;
+    surface->SlotBlkKind = input->kind;
+    surface->SlotBlkHeight = 0; /* XXX */
+    surface->SlotCacheWidth = VIC_CACHE_WIDTH_64Bx4; /* XXX */
+    surface->SlotSurfaceWidth = input->width - 1;
+    surface->SlotSurfaceHeight = input->height - 1;
+    surface->SlotLumaWidth = input->stride - 1;
+    surface->SlotLumaHeight = input->height - 1;
+    surface->SlotChromaWidth = 16383;
+    surface->SlotChromaHeight = 16383;
+
+    drm_tegra_bo_unmap(vic->config.bo);
+
+    return 0;
+}
+
+static int vic40_flip(struct vic *v, struct vic_image *output,
+                      struct vic_image *input)
+{
+    struct vic40 *vic = container_of(v, struct vic40, base);
+    SlotSurfaceConfig *surface;
+    SlotConfig *slot;
+    ConfigStruct *c;
+    int err;
+
+    err = drm_tegra_bo_map(vic->config.bo, (void **)&c);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    memset(c, 0, sizeof(*c));
+
+    c->outputConfig.TargetRectTop = 0;
+    c->outputConfig.TargetRectLeft = 0;
+    c->outputConfig.TargetRectRight = output->width - 1;
+    c->outputConfig.TargetRectBottom = output->height - 1;
+    c->outputConfig.BackgroundAlpha = 1023;
+    c->outputConfig.BackgroundR = 1023;
+    c->outputConfig.BackgroundG = 1023;
+    c->outputConfig.BackgroundB = 1023;
+    c->outputConfig.OutputFlipY = 1;
+
+    c->outputSurfaceConfig.OutPixelFormat = output->format;
+    c->outputSurfaceConfig.OutBlkKind = output->kind;
+    c->outputSurfaceConfig.OutBlkHeight = 0;
+    c->outputSurfaceConfig.OutSurfaceWidth = output->width - 1;
+    c->outputSurfaceConfig.OutSurfaceHeight = output->height - 1;
+    c->outputSurfaceConfig.OutLumaWidth = output->stride - 1;
+    c->outputSurfaceConfig.OutLumaHeight = output->height - 1;
+    c->outputSurfaceConfig.OutChromaWidth = 16383;
+    c->outputSurfaceConfig.OutChromaHeight = 16383;
+
+    slot = &c->slotStruct[0].slotConfig;
+    slot->SlotEnable = 1;
+    slot->CurrentFieldEnable = 1;
+    slot->PlanarAlpha = 1023;
+    slot->ConstantAlpha = 1;
+    slot->SourceRectLeft = 0 << 16;
+    slot->SourceRectRight = (input->width - 1) << 16;
+    slot->SourceRectTop = 0 << 16;
+    slot->SourceRectBottom = (input->height - 1) << 16;
+    slot->DestRectLeft = 0;
+    slot->DestRectRight = output->width - 1;
+    slot->DestRectTop = 0;
+    slot->DestRectBottom = output->height - 1;
+    slot->SoftClampHigh = 1023;
+
+    surface = &c->slotStruct[0].slotSurfaceConfig;
+    surface->SlotPixelFormat = input->format;
+    surface->SlotBlkKind = input->kind;
+    surface->SlotBlkHeight = 0; /* XXX */
+    surface->SlotCacheWidth = VIC_CACHE_WIDTH_64Bx4; /* XXX */
+    surface->SlotSurfaceWidth = input->width - 1;
+    surface->SlotSurfaceHeight = input->height - 1;
+    surface->SlotLumaWidth = input->stride - 1;
+    surface->SlotLumaHeight = input->height - 1;
+    surface->SlotChromaWidth = 16383;
+    surface->SlotChromaHeight = 16383;
+
+    drm_tegra_bo_unmap(vic->config.bo);
+
+    return 0;
+}
+
+static int vic40_execute(struct vic *v, struct drm_tegra_pushbuf *pushbuf,
+                         uint32_t **ptrp, struct vic_image *output,
+                         struct vic_image **inputs, unsigned int num_inputs)
+{
+    struct vic40 *vic = container_of(v, struct vic40, base);
+    unsigned int i;
+
+    if (num_inputs > 1)
+        return -EINVAL;
+
+    VIC_PUSH_METHOD(pushbuf, ptrp, NVB0B6_VIDEO_COMPOSITOR_SET_APPLICATION_ID, 1);
+    VIC_PUSH_METHOD(pushbuf, ptrp, NVB0B6_VIDEO_COMPOSITOR_SET_CONTROL_PARAMS, (sizeof(ConfigStruct) / 16) << 16);
+    VIC_PUSH_BUFFER(pushbuf, ptrp, NVB0B6_VIDEO_COMPOSITOR_SET_CONFIG_STRUCT_OFFSET, vic->config.map, 0, 0);
+    VIC_PUSH_BUFFER(pushbuf, ptrp, NVB0B6_VIDEO_COMPOSITOR_SET_OUTPUT_SURFACE_LUMA_OFFSET, output->map, 0, 0);
+
+    for (i = 0; i < num_inputs; i++)
+        VIC_PUSH_BUFFER(pushbuf, ptrp, NVB0B6_VIDEO_COMPOSITOR_SET_SURFACE0_SLOT0_LUMA_OFFSET, inputs[i]->map, 0, 0);
+
+    VIC_PUSH_METHOD(pushbuf, ptrp, NVB0B6_VIDEO_COMPOSITOR_EXECUTE, 1 << 8);
+
+    return 0;
+}
+
+static void vic40_free(struct vic *v)
+{
+    struct vic40 *vic = container_of(v, struct vic40, base);
+
+    drm_tegra_channel_unmap(vic->filter.map);
+    drm_tegra_bo_unref(vic->filter.bo);
+
+    drm_tegra_channel_unmap(vic->config.map);
+    drm_tegra_bo_unref(vic->config.bo);
+
+    drm_tegra_syncpoint_free(v->syncpt);
+
+    free(vic);
+}
+
+static const struct vic_ops vic40_ops = {
+    .fill = vic40_fill,
+    .blit = vic40_blit,
+    .flip = vic40_flip,
+    .execute = vic40_execute,
+    .free = vic40_free,
+};
+
+int vic40_new(struct drm_tegra *drm, struct drm_tegra_channel *channel,
+              struct vic **vicp)
+{
+    struct vic40 *vic;
+    void *ptr;
+    int err;
+
+    vic = calloc(1, sizeof(*vic));
+    if (!vic)
+        return -ENOMEM;
+
+    vic->base.drm = drm;
+    vic->base.channel = channel;
+    vic->base.ops = &vic40_ops;
+    vic->base.version = 0x21;
+
+    err = drm_tegra_syncpoint_new(drm, &vic->base.syncpt);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate syncpoint: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_new(drm, 0, 16384, &vic->config.bo);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate configuration structurer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_channel_map(channel, vic->config.bo, DRM_TEGRA_CHANNEL_MAP_READ,
+                                &vic->config.map);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_new(drm, 0, 16384, &vic->filter.bo);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate filter buffer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_map(vic->filter.bo, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to map filter buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    memset(ptr, 0, 16384);
+    drm_tegra_bo_unmap(vic->filter.bo);
+
+    err = drm_tegra_channel_map(channel, vic->filter.bo, DRM_TEGRA_CHANNEL_MAP_READ,
+                                &vic->filter.map);
+    if (err < 0) {
+        fprintf(stderr, "failed to map filter buffer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    if (vicp)
+        *vicp = &vic->base;
+
+    return 0;
+}
diff --git a/tests/tegra/vic40.h b/tests/tegra/vic40.h
new file mode 100644
index 00000000..a62301a8
--- /dev/null
+++ b/tests/tegra/vic40.h
@@ -0,0 +1,285 @@
+/*
+ * Copyright © 2016-2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifndef VIC40_H
+#define VIC40_H
+
+#include <stdint.h>
+
+#define NVB0B6_VIDEO_COMPOSITOR_SET_APPLICATION_ID 0x00000200
+#define NVB0B6_VIDEO_COMPOSITOR_EXECUTE 0x00000300
+#define NVB0B6_VIDEO_COMPOSITOR_SET_SURFACE0_SLOT0_LUMA_OFFSET 0x00000400
+#define NVB0B6_VIDEO_COMPOSITOR_SET_SURFACE0_SLOT0_CHROMA_U_OFFSET 0x00000404
+#define NVB0B6_VIDEO_COMPOSITOR_SET_SURFACE0_SLOT0_CHROMA_V_OFFSET 0x00000408
+#define NVB0B6_VIDEO_COMPOSITOR_SET_CONTROL_PARAMS 0x00000704
+#define NVB0B6_VIDEO_COMPOSITOR_SET_CONFIG_STRUCT_OFFSET 0x00000708
+#define NVB0B6_VIDEO_COMPOSITOR_SET_HIST_OFFSET 0x00000714
+#define NVB0B6_VIDEO_COMPOSITOR_SET_OUTPUT_SURFACE_LUMA_OFFSET 0x00000720
+
+typedef struct {
+    uint64_t SlotEnable : 1; /* 0 */
+    uint64_t DeNoise : 1; /* 1 */
+    uint64_t AdvancedDenoise : 1; /* 2 */
+    uint64_t CadenceDetect : 1; /* 3 */
+    uint64_t MotionMap : 1; /* 4 */
+    uint64_t MMapCombine : 1; /* 5 */
+    uint64_t IsEven : 1; /* 6 */
+    uint64_t ChromaEven : 1; /* 7 */
+    uint64_t CurrentFieldEnable : 1; /* 8 */
+    uint64_t PrevFieldEnable : 1; /* 9 */
+    uint64_t NextFieldEnable : 1; /* 10 */
+    uint64_t NextNrFieldEnable : 1; /* 11 */
+    uint64_t CurMotionFieldEnable : 1; /* 12 */
+    uint64_t PrevMotionFieldEnable : 1; /* 13 */
+    uint64_t PpMotionFieldEnable : 1; /* 14 */
+    uint64_t CombMotionFieldEnable : 1; /* 15 */
+    uint64_t FrameFormat : 4; /* 19..16 */
+    uint64_t FilterLengthY : 2; /* 21..20 */
+    uint64_t FilterLengthX : 2; /* 23..22 */
+    uint64_t Panoramic : 12; /* 35..24 */
+    uint64_t reserved1 : 22; /* 57..36 */
+    uint64_t DetailFltClamp : 6; /* 63..58 */
+    uint64_t FilterNoise : 10; /* 73..64 */
+    uint64_t FilterDetail : 10; /* 83..74 */
+    uint64_t ChromaNoise : 10; /* 93..84 */
+    uint64_t ChromaDetail : 10; /* 103..94 */
+    uint64_t DeinterlaceMode : 4; /* 107..104 */
+    uint64_t MotionAccumWeight : 3; /* 110..108 */
+    uint64_t NoiseIir : 11; /* 121..111 */
+    uint64_t LightLevel : 4; /* 125..122 */
+    uint64_t reserved4 : 2; /* 127..126 */
+    /* 128 */
+    uint64_t SoftClampLow : 10; /* 9..0 */
+    uint64_t SoftClampHigh : 10; /* 19..10 */
+    uint64_t reserved5 : 3; /* 22..20 */
+    uint64_t reserved6 : 9; /* 31..23 */
+    uint64_t PlanarAlpha : 10; /* 41..32 */
+    uint64_t ConstantAlpha : 1; /* 42 */
+    uint64_t StereoInterleave : 3; /* 45..43 */
+    uint64_t ClipEnabled : 1; /* 46 */
+    uint64_t ClearRectMask : 8; /* 54..47 */
+    uint64_t DegammaMode : 2; /* 56..55 */
+    uint64_t reserved7 : 1; /* 57 */
+    uint64_t DecompressEnable : 1; /* 58 */
+    uint64_t reserved9 : 5; /* 63..59 */
+    uint64_t DecompressCtbCount : 8; /* 71..64 */
+    uint64_t DecompressZbcColor : 32; /* 103..72 */
+    uint64_t reserved12 : 24; /* 127..104 */
+    /* 256 */
+    uint64_t SourceRectLeft : 30; /* 29..0 */
+    uint64_t reserved14 : 2; /* 31..30 */
+    uint64_t SourceRectRight : 30; /* 61..32 */
+    uint64_t reserved15 : 2; /* 63..62 */
+    uint64_t SourceRectTop : 30; /* 93..64 */
+    uint64_t reserved16 : 2; /* 95..94 */
+    uint64_t SourceRectBottom : 30; /* 125..96 */
+    uint64_t reserved17 : 2; /* 127..126 */
+    /* 384 */
+    uint64_t DestRectLeft : 14; /* 13..0 */
+    uint64_t reserved18 : 2; /* 15..14 */
+    uint64_t DestRectRight : 14; /* 29..16 */
+    uint64_t reserved19 : 2; /* 31..30 */
+    uint64_t DestRectTop : 14; /* 45..32 */
+    uint64_t reserved20 : 2; /* 47..46 */
+    uint64_t DestRectBottom : 14; /* 61..48 */
+    uint64_t reserved21 : 2; /* 63..62 */
+    uint64_t reserved22 : 32; /* 95..64 */
+    uint64_t reserved23 : 32; /* 127..96 */
+} SlotConfig;
+
+typedef struct {
+    uint64_t SlotPixelFormat : 7; /* 6..0 */
+    uint64_t SlotChromaLocHoriz : 2; /* 8..7 */
+    uint64_t SlotChromaLocVert : 2; /* 10..9 */
+    uint64_t SlotBlkKind : 4; /* 14..11 */
+    uint64_t SlotBlkHeight : 4; /* 18..15 */
+    uint64_t SlotCacheWidth : 3; /* 21..19 */
+    uint64_t reserved0 : 10; /* 31..22 */
+    uint64_t SlotSurfaceWidth : 14; /* 45..32 */
+    uint64_t SlotSurfaceHeight : 14; /* 59..46 */
+    uint64_t reserved1 : 4; /* 63..60 */
+    uint64_t SlotLumaWidth : 14; /* 77..64 */
+    uint64_t SlotLumaHeight : 14; /* 91..78 */
+    uint64_t reserved2 : 4; /* 95..92 */
+    uint64_t SlotChromaWidth : 14; /* 109..96 */
+    uint64_t SlotChromaHeight : 14; /* 123..110 */
+    uint64_t reserved3 : 4; /* 127..124 */
+} SlotSurfaceConfig;
+
+typedef struct {
+    uint64_t luma_coeff0 : 20; /* 19..0 */
+    uint64_t luma_coeff1 : 20; /* 39..20 */
+    uint64_t luma_coeff2 : 20; /* 59..40 */
+    uint64_t luma_r_shift : 4; /* 63..60 */
+    uint64_t luma_coeff3 : 20; /* 83..64 */
+    uint64_t LumaKeyLower : 10; /* 93..84 */
+    uint64_t LumaKeyUpper : 10; /* 103..94 */
+    uint64_t LumaKeyEnabled : 1; /* 104 */
+    uint64_t reserved0 : 2; /* 106..105 */
+    uint64_t reserved1 : 21; /* 127..107 */
+} LumaKeyStruct;
+
+typedef struct {
+    uint64_t matrix_coeff00 : 20; /* 19..0 */
+    uint64_t matrix_coeff10 : 20; /* 39..20 */
+    uint64_t matrix_coeff20 : 20; /* 59..40 */
+    uint64_t matrix_r_shift : 4; /* 63..60 */
+    uint64_t matrix_coeff01 : 20; /* 83..64 */
+    uint64_t matrix_coeff11 : 20; /* 103..84 */
+    uint64_t matrix_coeff21 : 20; /* 123..104 */
+    uint64_t reserved0 : 3; /* 126..124 */
+    uint64_t matrix_enable : 1; /* 127 */
+    /* 128 */
+    uint64_t matrix_coeff02 : 20; /* 19..0 */
+    uint64_t matrix_coeff12 : 20; /* 39..20 */
+    uint64_t matrix_coeff22 : 20; /* 59..40 */
+    uint64_t reserved1 : 4; /* 63..60 */
+    uint64_t matrix_coeff03 : 20; /* 83..64 */
+    uint64_t matrix_coeff13 : 20; /* 103..84 */
+    uint64_t matrix_coeff23 : 20; /* 123..104 */
+    uint64_t reserved2 : 4; /* 127..124 */
+} MatrixStruct;
+
+typedef struct {
+    uint64_t ClearRect0Left : 14; /* 13..0 */
+    uint64_t reserved0 : 2; /* 15..14 */
+    uint64_t ClearRect0Right : 14; /* 29..16 */
+    uint64_t reserved1 : 2; /* 31..30 */
+    uint64_t ClearRect0Top : 14; /* 45..32 */
+    uint64_t reserved2 : 2; /* 47..46 */
+    uint64_t ClearRect0Bottom : 14; /* 61..48 */
+    uint64_t reserved3 : 2; /* 63..62 */
+    uint64_t ClearRect1Left : 14; /* 77..64 */
+    uint64_t reserved4 : 2; /* 79..78 */
+    uint64_t ClearRect1Right : 14; /* 93..80 */
+    uint64_t reserved5 : 2; /* 95..94 */
+    uint64_t ClearRect1Top : 14; /* 109..96 */
+    uint64_t reserved6 : 2; /* 111..110 */
+    uint64_t ClearRect1Bottom : 14; /* 125..112 */
+    uint64_t reserved7 : 2; /* 127..126 */
+} ClearRectStruct;
+
+typedef struct {
+    uint64_t AlphaK1 : 10; /* 9..0 */
+    uint64_t reserved0 : 6; /* 15..10 */
+    uint64_t AlphaK2 : 10; /* 25..16 */
+    uint64_t reserved1 : 6; /* 31..26 */
+    uint64_t SrcFactCMatchSelect : 3; /* 34..32 */
+    uint64_t reserved2 : 1; /* 35 */
+    uint64_t DstFactCMatchSelect : 3; /* 38..36 */
+    uint64_t reserved3 : 1; /* 39 */
+    uint64_t SrcFactAMatchSelect : 3; /* 42..40 */
+    uint64_t reserved4 : 1; /* 43 */
+    uint64_t DstFactAMatchSelect : 3; /* 46..44 */
+    uint64_t reserved5 : 1; /* 47 */
+    uint64_t reserved6 : 4; /* 51..48 */
+    uint64_t reserved7 : 4; /* 55..52 */
+    uint64_t reserved8 : 4; /* 59..56 */
+    uint64_t reserved9 : 4; /* 63..60 */
+    uint64_t reserved10 : 2; /* 65..64 */
+    uint64_t OverrideR : 10; /* 75..66 */
+    uint64_t OverrideG : 10; /* 85..76 */
+    uint64_t OverrideB : 10; /* 95..86 */
+    uint64_t OverrideA : 10; /* 105..96 */
+    uint64_t reserved11 : 2; /* 107..106 */
+    uint64_t UseOverrideR : 1; /* 108 */
+    uint64_t UseOverrideG : 1; /* 109 */
+    uint64_t UseOverrideB : 1; /* 110 */
+    uint64_t UseOverrideA : 1; /* 111 */
+    uint64_t MaskR : 1; /* 112 */
+    uint64_t MaskG : 1; /* 113 */
+    uint64_t MaskB : 1; /* 114 */
+    uint64_t MaskA : 1; /* 115 */
+    uint64_t reserved12 : 12; /* 127..116 */
+} BlendingSlotStruct;
+
+typedef struct {
+    uint64_t AlphaFillMode : 3; /* 2..0 */
+    uint64_t AlphaFillSlot : 3; /* 5..3 */
+    uint64_t BackgroundAlpha : 10; /* 15..6 */
+    uint64_t BackgroundR : 10; /* 25..16 */
+    uint64_t BackgroundG : 10; /* 35..26 */
+    uint64_t BackgroundB : 10; /* 45..36 */
+    uint64_t RegammaMode : 2; /* 47..46 */
+    uint64_t OutputFlipX : 1; /* 48 */
+    uint64_t OutputFlipY : 1; /* 49 */
+    uint64_t OutputTranspose : 1; /* 50 */
+    uint64_t reserved1 : 1; /* 51 */
+    uint64_t reserved2 : 12; /* 63..52 */
+    uint64_t TargetRectLeft : 14; /* 77..64 */
+    uint64_t reserved3 : 2; /* 79..78 */
+    uint64_t TargetRectRight : 14; /* 93..80 */
+    uint64_t reserved4 : 2; /* 95..94 */
+    uint64_t TargetRectTop : 14; /* 109..96 */
+    uint64_t reserved5 : 2; /* 111..110 */
+    uint64_t TargetRectBottom : 14; /* 125..112 */
+    uint64_t reserved6 : 2; /* 127..126 */
+} OutputConfig;
+
+typedef struct {
+    uint64_t OutPixelFormat : 7; /* 6..0 */
+    uint64_t OutChromaLocHoriz : 2; /* 8..7 */
+    uint64_t OutChromaLocVert : 2; /* 10..9 */
+    uint64_t OutBlkKind : 4; /* 14..11 */
+    uint64_t OutBlkHeight : 4; /* 18..15 */
+    uint64_t reserved0 : 3; /* 21..19 */
+    uint64_t reserved1 : 10; /* 31..22 */
+    uint64_t OutSurfaceWidth : 14; /* 45..32 */
+    uint64_t OutSurfaceHeight : 14; /* 59..46 */
+    uint64_t reserved2 : 4; /* 63..60 */
+    uint64_t OutLumaWidth : 14; /* 77..64 */
+    uint64_t OutLumaHeight : 14; /* 91..78 */
+    uint64_t reserved3 : 4; /* 95..92 */
+    uint64_t OutChromaWidth : 14; /* 109..96 */
+    uint64_t OutChromaHeight : 14; /* 123..110 */
+    uint64_t reserved4 : 4; /* 127..124 */
+} OutputSurfaceConfig;
+
+typedef struct {
+    uint64_t DownsampleHoriz : 11; /* 10..0 */
+    uint64_t reserved0 : 5; /* 15..11 */
+    uint64_t DownsampleVert : 11; /* 26..16 */
+    uint64_t reserved1 : 5; /* 31..27 */
+    uint64_t reserved2 : 32; /* 63..32 */
+    uint64_t reserved3 : 32; /* 95..64 */
+    uint64_t reserved4 : 32; /* 127..96 */
+} PipeConfig;
+
+typedef struct {
+    SlotConfig slotConfig;
+    SlotSurfaceConfig slotSurfaceConfig;
+    LumaKeyStruct lumaKeyStruct;
+    MatrixStruct colorMatrixStruct;
+    MatrixStruct gamutMatrixStruct;
+    BlendingSlotStruct blendingSlotStruct;
+} SlotStruct;
+
+typedef struct {
+    PipeConfig pipeConfig;
+    OutputConfig outputConfig;
+    OutputSurfaceConfig outputSurfaceConfig;
+    MatrixStruct outColorMatrixStruct;
+    ClearRectStruct clearRectStruct[4];
+    SlotStruct slotStruct[8];
+} ConfigStruct;
+
+#endif
diff --git a/tests/tegra/vic41.c b/tests/tegra/vic41.c
new file mode 100644
index 00000000..edbc748d
--- /dev/null
+++ b/tests/tegra/vic41.c
@@ -0,0 +1,342 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#include <errno.h>
+#include <string.h>
+
+#include "private.h"
+#include "tegra.h"
+#include "vic.h"
+#include "vic41.h"
+
+struct vic41 {
+    struct vic base;
+
+    struct {
+        struct drm_tegra_mapping *map;
+        struct drm_tegra_bo *bo;
+    } config;
+
+    struct {
+        struct drm_tegra_mapping *map;
+        struct drm_tegra_bo *bo;
+    } filter;
+};
+
+static int vic41_fill(struct vic *v, struct vic_image *output,
+                      unsigned int left, unsigned int top,
+                      unsigned int right, unsigned int bottom,
+                      unsigned int alpha, unsigned int red,
+                      unsigned int green, unsigned int blue)
+{
+    struct vic41 *vic = container_of(v, struct vic41, base);
+    ConfigStruct *c;
+    int err;
+
+    err = drm_tegra_bo_map(vic->config.bo, (void **)&c);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    memset(c, 0, sizeof(*c));
+
+    c->outputConfig.TargetRectTop = top;
+    c->outputConfig.TargetRectLeft = left;
+    c->outputConfig.TargetRectRight = right;
+    c->outputConfig.TargetRectBottom = bottom;
+    c->outputConfig.BackgroundAlpha = alpha;
+    c->outputConfig.BackgroundR = red;
+    c->outputConfig.BackgroundG = green;
+    c->outputConfig.BackgroundB = blue;
+
+    c->outputSurfaceConfig.OutPixelFormat = output->format;
+    c->outputSurfaceConfig.OutBlkKind = output->kind;
+    c->outputSurfaceConfig.OutBlkHeight = 0;
+    c->outputSurfaceConfig.OutSurfaceWidth = output->width - 1;
+    c->outputSurfaceConfig.OutSurfaceHeight = output->height - 1;
+    c->outputSurfaceConfig.OutLumaWidth = output->stride - 1;
+    c->outputSurfaceConfig.OutLumaHeight = output->height - 1;
+    c->outputSurfaceConfig.OutChromaWidth = 16383;
+    c->outputSurfaceConfig.OutChromaHeight = 16383;
+
+    drm_tegra_bo_unmap(vic->config.bo);
+
+    return 0;
+}
+
+static int vic41_blit(struct vic *v, struct vic_image *output,
+                      struct vic_image *input)
+{
+    struct vic41 *vic = container_of(v, struct vic41, base);
+    SlotSurfaceConfig *surface;
+    SlotConfig *slot;
+    ConfigStruct *c;
+    int err;
+
+    err = drm_tegra_bo_map(vic->config.bo, (void **)&c);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    memset(c, 0, sizeof(*c));
+
+    c->outputConfig.TargetRectTop = 0;
+    c->outputConfig.TargetRectLeft = 0;
+    c->outputConfig.TargetRectRight = output->width - 1;
+    c->outputConfig.TargetRectBottom = output->height - 1;
+    c->outputConfig.BackgroundAlpha = 255;
+    c->outputConfig.BackgroundR = 1023;
+    c->outputConfig.BackgroundG = 1023;
+    c->outputConfig.BackgroundB = 1023;
+
+    c->outputSurfaceConfig.OutPixelFormat = output->format;
+    c->outputSurfaceConfig.OutBlkKind = output->kind;
+    c->outputSurfaceConfig.OutBlkHeight = 0;
+    c->outputSurfaceConfig.OutSurfaceWidth = output->width - 1;
+    c->outputSurfaceConfig.OutSurfaceHeight = output->height - 1;
+    c->outputSurfaceConfig.OutLumaWidth = output->stride - 1;
+    c->outputSurfaceConfig.OutLumaHeight = output->height - 1;
+    c->outputSurfaceConfig.OutChromaWidth = 16383;
+    c->outputSurfaceConfig.OutChromaHeight = 16383;
+
+    slot = &c->slotStruct[0].slotConfig;
+    slot->SlotEnable = 1;
+    slot->CurrentFieldEnable = 1;
+    slot->PlanarAlpha = 255;
+    slot->ConstantAlpha = 1;
+    slot->SourceRectLeft = 0 << 16;
+    slot->SourceRectRight = (input->width - 1) << 16;
+    slot->SourceRectTop = 0 << 16;
+    slot->SourceRectBottom = (input->height - 1) << 16;
+    slot->DestRectLeft = 0;
+    slot->DestRectRight = output->width - 1;
+    slot->DestRectTop = 0;
+    slot->DestRectBottom = output->height - 1;
+    slot->SoftClampHigh = 1023;
+
+    surface = &c->slotStruct[0].slotSurfaceConfig;
+    surface->SlotPixelFormat = input->format;
+    surface->SlotBlkKind = input->kind;
+    surface->SlotBlkHeight = 0; /* XXX */
+    surface->SlotCacheWidth = VIC_CACHE_WIDTH_64Bx4; /* XXX */
+    surface->SlotSurfaceWidth = input->width - 1;
+    surface->SlotSurfaceHeight = input->height - 1;
+    surface->SlotLumaWidth = input->stride - 1;
+    surface->SlotLumaHeight = input->height - 1;
+    surface->SlotChromaWidth = 16383;
+    surface->SlotChromaHeight = 16383;
+
+    drm_tegra_bo_unmap(vic->config.bo);
+
+    return 0;
+}
+
+static int vic41_flip(struct vic *v, struct vic_image *output,
+                      struct vic_image *input)
+{
+    struct vic41 *vic = container_of(v, struct vic41, base);
+    SlotSurfaceConfig *surface;
+    SlotConfig *slot;
+    ConfigStruct *c;
+    int err;
+
+    err = drm_tegra_bo_map(vic->config.bo, (void **)&c);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    memset(c, 0, sizeof(*c));
+
+    c->outputConfig.TargetRectTop = 0;
+    c->outputConfig.TargetRectLeft = 0;
+    c->outputConfig.TargetRectRight = output->width - 1;
+    c->outputConfig.TargetRectBottom = output->height - 1;
+    c->outputConfig.BackgroundAlpha = 255;
+    c->outputConfig.BackgroundR = 1023;
+    c->outputConfig.BackgroundG = 1023;
+    c->outputConfig.BackgroundB = 1023;
+    c->outputConfig.OutputFlipY = 1;
+
+    c->outputSurfaceConfig.OutPixelFormat = output->format;
+    c->outputSurfaceConfig.OutBlkKind = output->kind;
+    c->outputSurfaceConfig.OutBlkHeight = 0;
+    c->outputSurfaceConfig.OutSurfaceWidth = output->width - 1;
+    c->outputSurfaceConfig.OutSurfaceHeight = output->height - 1;
+    c->outputSurfaceConfig.OutLumaWidth = output->stride - 1;
+    c->outputSurfaceConfig.OutLumaHeight = output->height - 1;
+    c->outputSurfaceConfig.OutChromaWidth = 16383;
+    c->outputSurfaceConfig.OutChromaHeight = 16383;
+
+    slot = &c->slotStruct[0].slotConfig;
+    slot->SlotEnable = 1;
+    slot->CurrentFieldEnable = 1;
+    slot->PlanarAlpha = 255;
+    slot->ConstantAlpha = 1;
+    slot->SourceRectLeft = 0 << 16;
+    slot->SourceRectRight = (input->width - 1) << 16;
+    slot->SourceRectTop = 0 << 16;
+    slot->SourceRectBottom = (input->height - 1) << 16;
+    slot->DestRectLeft = 0;
+    slot->DestRectRight = output->width - 1;
+    slot->DestRectTop = 0;
+    slot->DestRectBottom = output->height - 1;
+    slot->SoftClampHigh = 1023;
+
+    surface = &c->slotStruct[0].slotSurfaceConfig;
+    surface->SlotPixelFormat = input->format;
+    surface->SlotBlkKind = input->kind;
+    surface->SlotBlkHeight = 0; /* XXX */
+    surface->SlotCacheWidth = VIC_CACHE_WIDTH_64Bx4; /* XXX */
+    surface->SlotSurfaceWidth = input->width - 1;
+    surface->SlotSurfaceHeight = input->height - 1;
+    surface->SlotLumaWidth = input->stride - 1;
+    surface->SlotLumaHeight = input->height - 1;
+    surface->SlotChromaWidth = 16383;
+    surface->SlotChromaHeight = 16383;
+
+    drm_tegra_bo_unmap(vic->config.bo);
+
+    return 0;
+}
+
+static int vic41_execute(struct vic *v, struct drm_tegra_pushbuf *pushbuf,
+                         uint32_t **ptrp, struct vic_image *output,
+                         struct vic_image **inputs, unsigned int num_inputs)
+{
+    struct vic41 *vic = container_of(v, struct vic41, base);
+    unsigned int i;
+
+    if (num_inputs > 1)
+        return -EINVAL;
+
+    VIC_PUSH_METHOD(pushbuf, ptrp, NVB1B6_VIDEO_COMPOSITOR_SET_APPLICATION_ID, 1);
+    VIC_PUSH_METHOD(pushbuf, ptrp, NVB1B6_VIDEO_COMPOSITOR_SET_CONTROL_PARAMS, (sizeof(ConfigStruct) / 16) << 16);
+    VIC_PUSH_BUFFER(pushbuf, ptrp, NVB1B6_VIDEO_COMPOSITOR_SET_CONFIG_STRUCT_OFFSET, vic->config.map, 0, 0);
+    VIC_PUSH_BUFFER(pushbuf, ptrp, NVB1B6_VIDEO_COMPOSITOR_SET_FILTER_STRUCT_OFFSET, vic->filter.map, 0, 0);
+    VIC_PUSH_BUFFER(pushbuf, ptrp, NVB1B6_VIDEO_COMPOSITOR_SET_OUTPUT_SURFACE_LUMA_OFFSET, output->map, 0, 0);
+
+    for (i = 0; i < num_inputs; i++) {
+        uint32_t method = NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE0_LUMA_OFFSET(0) + (i * 3) * 4;
+
+        VIC_PUSH_BUFFER(pushbuf, ptrp, method, inputs[i]->map, 0, 0);
+    }
+
+    VIC_PUSH_METHOD(pushbuf, ptrp, NVB1B6_VIDEO_COMPOSITOR_EXECUTE, 1 << 8);
+
+    return 0;
+}
+
+static void vic41_free(struct vic *v)
+{
+    struct vic41 *vic = container_of(v, struct vic41, base);
+
+    drm_tegra_channel_unmap(vic->filter.map);
+    drm_tegra_bo_unref(vic->filter.bo);
+
+    drm_tegra_channel_unmap(vic->config.map);
+    drm_tegra_bo_unref(vic->config.bo);
+
+    drm_tegra_syncpoint_free(v->syncpt);
+
+    free(vic);
+}
+
+static const struct vic_ops vic41_ops = {
+    .fill = vic41_fill,
+    .blit = vic41_blit,
+    .flip = vic41_flip,
+    .execute = vic41_execute,
+    .free = vic41_free,
+};
+
+int vic41_new(struct drm_tegra *drm, struct drm_tegra_channel *channel,
+              struct vic **vicp)
+{
+    struct vic41 *vic;
+    void *ptr;
+    int err;
+
+    vic = calloc(1, sizeof(*vic));
+    if (!vic)
+        return -ENOMEM;
+
+    vic->base.drm = drm;
+    vic->base.channel = channel;
+    vic->base.ops = &vic41_ops;
+    vic->base.version = 0x18;
+
+    err = drm_tegra_syncpoint_new(drm, &vic->base.syncpt);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate syncpoint: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_new(drm, 0, 16384, &vic->config.bo);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate configuration structurer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_channel_map(channel, vic->config.bo, DRM_TEGRA_CHANNEL_MAP_READ,
+                                &vic->config.map);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_new(drm, 0, 16384, &vic->filter.bo);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate filter buffer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_map(vic->filter.bo, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to map filter buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    memset(ptr, 0, 16384);
+    drm_tegra_bo_unmap(vic->filter.bo);
+
+    err = drm_tegra_channel_map(channel, vic->filter.bo, DRM_TEGRA_CHANNEL_MAP_READ,
+                                &vic->filter.map);
+    if (err < 0) {
+        fprintf(stderr, "failed to map filter buffer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    if (vicp)
+        *vicp = &vic->base;
+
+    return 0;
+}
diff --git a/tests/tegra/vic41.h b/tests/tegra/vic41.h
new file mode 100644
index 00000000..07d7019a
--- /dev/null
+++ b/tests/tegra/vic41.h
@@ -0,0 +1,372 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifndef VIC41_H
+#define VIC41_H
+
+#include <stdint.h>
+
+#define NVB1B6_VIDEO_COMPOSITOR_SET_APPLICATION_ID 0x00000200
+#define NVB1B6_VIDEO_COMPOSITOR_EXECUTE 0x00000300
+#define NVB1B6_VIDEO_COMPOSITOR_SET_PICTURE_INDEX 0x00000700
+#define NVB1B6_VIDEO_COMPOSITOR_SET_CONTROL_PARAMS 0x00000704
+#define NVB1B6_VIDEO_COMPOSITOR_SET_CONFIG_STRUCT_OFFSET 0x00000708
+#define NVB1B6_VIDEO_COMPOSITOR_SET_FILTER_STRUCT_OFFSET 0x0000070c
+#define NVB1B6_VIDEO_COMPOSITOR_SET_HIST_OFFSET 0x00000714
+#define NVB1B6_VIDEO_COMPOSITOR_SET_OUTPUT_SURFACE_LUMA_OFFSET 0x00000720
+#define NVB1B6_VIDEO_COMPOSITOR_SET_HISTORY_BUFFER_OFFSET(slot) (0x00000780 + (slot) * 4)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE0_LUMA_OFFSET(slot) (0x00001200 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE0_CHROMA_U_OFFSET(slot) (0x00001204 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE0_CHROMA_V_OFFSET(slot) (0x00001208 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE1_LUMA_OFFSET(slot) (0x0000120c + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE1_CHROMA_U_OFFSET(slot) (0x00001210 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE1_CHROMA_V_OFFSET(slot) (0x00001214 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE2_LUMA_OFFSET(slot) (0x00001218 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE2_CHROMA_U_OFFSET(slot) (0x0000121c + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE2_CHROMA_V_OFFSET(slot) (0x00001220 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE3_LUMA_OFFSET(slot) (0x00001224 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE3_CHROMA_U_OFFSET(slot) (0x00001228 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE3_CHROMA_V_OFFSET(slot) (0x0000122c + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE4_LUMA_OFFSET(slot) (0x00001230 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE4_CHROMA_U_OFFSET(slot) (0x00001234 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE4_CHROMA_V_OFFSET(slot) (0x00001238 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE5_LUMA_OFFSET(slot) (0x0000123c + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE5_CHROMA_U_OFFSET(slot) (0x00001240 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE5_CHROMA_V_OFFSET(slot) (0x00001244 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE6_LUMA_OFFSET(slot) (0x00001248 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE6_CHROMA_U_OFFSET(slot) (0x0000124c + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE6_CHROMA_V_OFFSET(slot) (0x00001250 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE7_LUMA_OFFSET(slot) (0x00001254 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE7_CHROMA_U_OFFSET(slot) (0x00001258 + (slot) * 0x00000060)
+#define NVB1B6_VIDEO_COMPOSITOR_SET_SURFACE7_CHROMA_V_OFFSET(slot) (0x0000125c + (slot) * 0x00000060)
+
+typedef struct {
+    uint64_t SlotEnable : 1; /* 0 */
+    uint64_t DeNoise : 1; /* 1 */
+    uint64_t AdvancedDenoise : 1; /* 2 */
+    uint64_t CadenceDetect : 1; /* 3 */
+    uint64_t MotionMap : 1; /* 4 */
+    uint64_t MMapCombine : 1; /* 5 */
+    uint64_t IsEven : 1; /* 6 */
+    uint64_t ChromaEven : 1; /* 7 */
+    uint64_t CurrentFieldEnable : 1; /* 8 */
+    uint64_t PrevFieldEnable : 1; /* 9 */
+    uint64_t NextFieldEnable : 1; /* 10 */
+    uint64_t NextNrFieldEnable : 1; /* 11 */
+    uint64_t CurMotionFieldEnable : 1; /* 12 */
+    uint64_t PrevMotionFieldEnable : 1; /* 13 */
+    uint64_t PpMotionFieldEnable : 1; /* 14 */
+    uint64_t CombMotionFieldEnable : 1; /* 15 */
+    uint64_t FrameFormat : 4; /* 19..16 */
+    uint64_t FilterLengthY : 2; /* 21..20 */
+    uint64_t FilterLengthX : 2; /* 23..22 */
+    uint64_t Panoramic : 12; /* 35..24 */
+    uint64_t ChromaUpLengthY : 2; /* 37..36 */
+    uint64_t ChromaUpLengthX : 2; /* 39..38 */
+    uint64_t reserved1 : 18; /* 57..40 */
+    uint64_t DetailFltClamp : 6; /* 63..58 */
+    uint64_t FilterNoise : 10; /* 73..64 */
+    uint64_t FilterDetail : 10; /* 83..74 */
+    uint64_t ChromaNoise : 10; /* 93..84 */
+    uint64_t ChromaDetail : 10; /* 103..94 */
+    uint64_t DeinterlaceMode : 4; /* 107..104 */
+    uint64_t MotionAccumWeight : 3; /* 110..108 */
+    uint64_t NoiseIir : 11; /* 121..111 */
+    uint64_t LightLevel : 4; /* 125..122 */
+    uint64_t reserved4 : 2; /* 127..126 */
+    /* 128 */
+    uint64_t SoftClampLow : 10; /* 9..0 */
+    uint64_t SoftClampHigh : 10; /* 19..10 */
+    uint64_t reserved5 : 12; /* 31..20 */
+    uint64_t reserved6 : 2; /* 33..32 */
+    uint64_t PlanarAlpha : 8; /* 41..34 */
+    uint64_t ConstantAlpha : 1; /* 42 */
+    uint64_t StereoInterleave : 3; /* 45..43 */
+    uint64_t ClipEnabled : 1; /* 46 */
+    uint64_t ClearRectMask : 8; /* 54..47 */
+    uint64_t DegammaMode : 2; /* 56..55 */
+    uint64_t reserved7 : 1; /* 57 */
+    uint64_t DecompressEnable : 1; /* 58 */
+    uint64_t DecompressKind : 4; /* 62..59 */
+    uint64_t reserved9 : 1; /* 63 */
+    uint64_t DecompressCtbCount : 8; /* 71..64 */
+    uint64_t DecompressZbcColor : 32; /* 103..72 */
+    uint64_t reserved12 : 24; /* 127..104 */
+    /* 256 */
+    uint64_t SourceRectLeft : 30; /* 29..0 */
+    uint64_t reserved14 : 2; /* 31..30 */
+    uint64_t SourceRectRight : 30; /* 61..32 */
+    uint64_t reserved15 : 2; /* 63..62 */
+    uint64_t SourceRectTop : 30; /* 93..64 */
+    uint64_t reserved16 : 2; /* 95..94 */
+    uint64_t SourceRectBottom : 30; /* 125..96 */
+    uint64_t reserved17 : 2; /* 127..126 */
+    /* 384 */
+    uint64_t DestRectLeft : 14; /* 13..0 */
+    uint64_t reserved18 : 2; /* 15..14 */
+    uint64_t DestRectRight : 14; /* 29..16 */
+    uint64_t reserved19 : 2; /* 31..30 */
+    uint64_t DestRectTop : 14; /* 45..32 */
+    uint64_t reserved20 : 2; /* 47..46 */
+    uint64_t DestRectBottom : 14; /* 61..48 */
+    uint64_t reserved21 : 2; /* 63..62 */
+    uint64_t reserved22 : 32; /* 95..64 */
+    uint64_t reserved23 : 32; /* 127..96 */
+} SlotConfig;
+
+typedef struct {
+    uint64_t SlotPixelFormat : 7; /* 6..0 */
+    uint64_t SlotChromaLocHoriz : 2; /* 8..7 */
+    uint64_t SlotChromaLocVert : 2; /* 10..9 */
+    uint64_t SlotBlkKind : 4; /* 14..11 */
+    uint64_t SlotBlkHeight : 4; /* 18..15 */
+    uint64_t SlotCacheWidth : 3; /* 21..19 */
+    uint64_t reserved0 : 10; /* 31..22 */
+    uint64_t SlotSurfaceWidth : 14; /* 45..32 */
+    uint64_t SlotSurfaceHeight : 14; /* 59..46 */
+    uint64_t reserved1 : 4; /* 63..60 */
+    uint64_t SlotLumaWidth : 14; /* 77..64 */
+    uint64_t SlotLumaHeight : 14; /* 91..78 */
+    uint64_t reserved2 : 4; /* 95..92 */
+    uint64_t SlotChromaWidth : 14; /* 109..96 */
+    uint64_t SlotChromaHeight : 14; /* 123..110 */
+    uint64_t reserved3 : 4; /* 127..124 */
+} SlotSurfaceConfig;
+
+typedef struct {
+    uint64_t luma_coeff0 : 20; /* 19..0 */
+    uint64_t luma_coeff1 : 20; /* 39..20 */
+    uint64_t luma_coeff2 : 20; /* 59..40 */
+    uint64_t luma_r_shift : 4; /* 63..60 */
+    uint64_t luma_coeff3 : 20; /* 83..64 */
+    uint64_t LumaKeyLower : 10; /* 93..84 */
+    uint64_t LumaKeyUpper : 10; /* 103..94 */
+    uint64_t LumaKeyEnabled : 1; /* 104 */
+    uint64_t reserved0 : 2; /* 106..105 */
+    uint64_t reserved1 : 21; /* 127..107 */
+} LumaKeyStruct;
+
+typedef struct {
+    uint64_t matrix_coeff00 : 20; /* 19..0 */
+    uint64_t matrix_coeff10 : 20; /* 39..20 */
+    uint64_t matrix_coeff20 : 20; /* 59..40 */
+    uint64_t matrix_r_shift : 4; /* 63..60 */
+    uint64_t matrix_coeff01 : 20; /* 83..64 */
+    uint64_t matrix_coeff11 : 20; /* 103..84 */
+    uint64_t matrix_coeff21 : 20; /* 123..104 */
+    uint64_t reserved0 : 3; /* 126..124 */
+    uint64_t matrix_enable : 1; /* 127 */
+    /* 128 */
+    uint64_t matrix_coeff02 : 20; /* 19..0 */
+    uint64_t matrix_coeff12 : 20; /* 39..20 */
+    uint64_t matrix_coeff22 : 20; /* 59..40 */
+    uint64_t reserved1 : 4; /* 63..60 */
+    uint64_t matrix_coeff03 : 20; /* 83..64 */
+    uint64_t matrix_coeff13 : 20; /* 103..84 */
+    uint64_t matrix_coeff23 : 20; /* 123..104 */
+    uint64_t reserved2 : 4; /* 127..124 */
+} MatrixStruct;
+
+typedef struct {
+    uint64_t ClearRect0Left : 14; /* 13..0 */
+    uint64_t reserved0 : 2; /* 15..14 */
+    uint64_t ClearRect0Right : 14; /* 29..16 */
+    uint64_t reserved1 : 2; /* 31..30 */
+    uint64_t ClearRect0Top : 14; /* 45..32 */
+    uint64_t reserved2 : 2; /* 47..46 */
+    uint64_t ClearRect0Bottom : 14; /* 61..48 */
+    uint64_t reserved3 : 2; /* 63..62 */
+    uint64_t ClearRect1Left : 14; /* 77..64 */
+    uint64_t reserved4 : 2; /* 79..78 */
+    uint64_t ClearRect1Right : 14; /* 93..80 */
+    uint64_t reserved5 : 2; /* 95..94 */
+    uint64_t ClearRect1Top : 14; /* 109..96 */
+    uint64_t reserved6 : 2; /* 111..110 */
+    uint64_t ClearRect1Bottom : 14; /* 125..112 */
+    uint64_t reserved7 : 2; /* 127..126 */
+} ClearRectStruct;
+
+typedef struct {
+    uint64_t reserved0 : 2; /* 1..0 */
+    uint64_t AlphaK1 : 8; /* 9..2 */
+    uint64_t reserved1 : 6; /* 17..10 */
+    uint64_t AlphaK2 : 8; /* 25..18 */
+    uint64_t reserved2 : 6; /* 31..26 */
+    uint64_t SrcFactCMatchSelect : 3; /* 34..32 */
+    uint64_t reserved3 : 1; /* 35 */
+    uint64_t DstFactCMatchSelect : 3; /* 38..36 */
+    uint64_t reserved4 : 1; /* 39 */
+    uint64_t SrcFactAMatchSelect : 3; /* 42..40 */
+    uint64_t reserved5 : 1; /* 43 */
+    uint64_t DstFactAMatchSelect : 3; /* 46..44 */
+    uint64_t reserved6 : 1; /* 47 */
+    uint64_t reserved7 : 4; /* 51..48 */
+    uint64_t reserved8 : 4; /* 55..52 */
+    uint64_t reserved9 : 4; /* 59..56 */
+    uint64_t reserved10 : 4; /* 63..60 */
+    uint64_t reserved11 : 2; /* 65..64 */
+    uint64_t OverrideR : 10; /* 75..66 */
+    uint64_t OverrideG : 10; /* 85..76 */
+    uint64_t OverrideB : 10; /* 95..86 */
+    uint64_t reserved12 : 2; /* 97..96 */
+    uint64_t OverrideA : 8; /* 105..98 */
+    uint64_t reserved13 : 2; /* 107..106 */
+    uint64_t UseOverrideR : 1; /* 108 */
+    uint64_t UseOverrideG : 1; /* 109 */
+    uint64_t UseOverrideB : 1; /* 110 */
+    uint64_t UseOverrideA : 1; /* 111 */
+    uint64_t MaskR : 1; /* 112 */
+    uint64_t MaskG : 1; /* 113 */
+    uint64_t MaskB : 1; /* 114 */
+    uint64_t MaskA : 1; /* 115 */
+    uint64_t reserved14 : 12; /* 127..116 */
+} BlendingSlotStruct;
+
+typedef struct {
+    uint64_t AlphaFillMode : 3; /* 2..0 */
+    uint64_t AlphaFillSlot : 3; /* 5..3 */
+    uint64_t reserved0 : 2; /* 6..5 */
+    uint64_t BackgroundAlpha : 8; /* 15..7 */
+    uint64_t BackgroundR : 10; /* 25..16 */
+    uint64_t BackgroundG : 10; /* 35..26 */
+    uint64_t BackgroundB : 10; /* 45..36 */
+    uint64_t RegammaMode : 2; /* 47..46 */
+    uint64_t OutputFlipX : 1; /* 48 */
+    uint64_t OutputFlipY : 1; /* 49 */
+    uint64_t OutputTranspose : 1; /* 50 */
+    uint64_t reserved1 : 1; /* 51 */
+    uint64_t reserved2 : 12; /* 63..52 */
+    uint64_t TargetRectLeft : 14; /* 77..64 */
+    uint64_t reserved3 : 2; /* 79..78 */
+    uint64_t TargetRectRight : 14; /* 93..80 */
+    uint64_t reserved4 : 2; /* 95..94 */
+    uint64_t TargetRectTop : 14; /* 109..96 */
+    uint64_t reserved5 : 2; /* 111..110 */
+    uint64_t TargetRectBottom : 14; /* 125..112 */
+    uint64_t reserved6 : 2; /* 127..126 */
+} OutputConfig;
+
+typedef struct {
+    uint64_t OutPixelFormat : 7; /* 6..0 */
+    uint64_t OutChromaLocHoriz : 2; /* 8..7 */
+    uint64_t OutChromaLocVert : 2; /* 10..9 */
+    uint64_t OutBlkKind : 4; /* 14..11 */
+    uint64_t OutBlkHeight : 4; /* 18..15 */
+    uint64_t reserved0 : 3; /* 21..19 */
+    uint64_t reserved1 : 10; /* 31..22 */
+    uint64_t OutSurfaceWidth : 14; /* 45..32 */
+    uint64_t OutSurfaceHeight : 14; /* 59..46 */
+    uint64_t reserved2 : 4; /* 63..60 */
+    uint64_t OutLumaWidth : 14; /* 77..64 */
+    uint64_t OutLumaHeight : 14; /* 91..78 */
+    uint64_t reserved3 : 4; /* 95..92 */
+    uint64_t OutChromaWidth : 14; /* 109..96 */
+    uint64_t OutChromaHeight : 14; /* 123..110 */
+    uint64_t reserved4 : 4; /* 127..124 */
+} OutputSurfaceConfig;
+
+typedef struct {
+    uint64_t f00 : 10; /* 9..0 */
+    uint64_t f10 : 10; /* 19..10 */
+    uint64_t f20 : 10; /* 29..20 */
+    uint64_t reserved0 : 2; /* 31..30 */
+    uint64_t f01 : 10; /* 41..32 */
+    uint64_t f11 : 10; /* 51..42 */
+    uint64_t f21 : 10; /* 61..52 */
+    uint64_t reserved1 : 2; /* 63..62 */
+    uint64_t f02 : 10; /* 73..64 */
+    uint64_t f12 : 10; /* 83..74 */
+    uint64_t f22 : 10; /* 93..84 */
+    uint64_t reserved2 : 2; /* 95..94 */
+    uint64_t f03 : 10; /* 105..96 */
+    uint64_t f13 : 10; /* 115..106 */
+    uint64_t f23 : 10; /* 125..116 */
+    uint64_t reserved3 : 2; /* 127..126 */
+} FilterCoeffStruct;
+
+typedef struct {
+    uint64_t DownsampleHoriz : 11; /* 10..0 */
+    uint64_t reserved0 : 5; /* 15..11 */
+    uint64_t DownsampleVert : 11; /* 26..16 */
+    uint64_t reserved1 : 5; /* 31..27 */
+    uint64_t reserved2 : 32; /* 63..32 */
+    uint64_t reserved3 : 32; /* 95..64 */
+    uint64_t reserved4 : 32; /* 127..96 */
+} PipeConfig;
+
+typedef struct {
+    uint64_t OldCadence : 32; /* 31..0 */
+    uint64_t OldDiff : 32; /* 63..32 */
+    uint64_t OldWeave : 32; /* 95..64 */
+    uint64_t OlderWeave : 32; /* 127..96 */
+} SlotHistoryBuffer;
+
+typedef struct {
+    uint64_t crc0 : 32; /* 31..0 */
+    uint64_t crc1 : 32; /* 63..32 */
+    uint64_t crc2 : 32; /* 95..64 */
+    uint64_t crc3 : 32; /* 127..96 */
+} PartitionCrcStruct;
+
+typedef struct {
+    uint64_t crc0 : 32; /* 31..0 */
+    uint64_t crc1 : 32; /* 63..32 */
+} SlotCrcStruct;
+
+typedef struct {
+    uint64_t ErrorStatus : 32; /* 31..0 */
+    uint64_t CycleCount : 32; /* 63..32 */
+    uint64_t reserved0 : 32; /* 95..64 */
+    uint64_t reserved1 : 32; /* 127..96 */
+} StatusStruct;
+
+typedef struct {
+    SlotConfig slotConfig;
+    SlotSurfaceConfig slotSurfaceConfig;
+    LumaKeyStruct lumaKeyStruct;
+    MatrixStruct colorMatrixStruct;
+    MatrixStruct gamutMatrixStruct;
+    BlendingSlotStruct blendingSlotStruct;
+} SlotStruct;
+
+typedef struct {
+    FilterCoeffStruct filterCoeffStruct[520];
+} FilterStruct;
+
+typedef struct {
+    PipeConfig pipeConfig;
+    OutputConfig outputConfig;
+    OutputSurfaceConfig outputSurfaceConfig;
+    MatrixStruct outColorMatrixStruct;
+    ClearRectStruct clearRectStruct[4];
+    SlotStruct slotStruct[16];
+} ConfigStruct;
+
+typedef struct {
+    PartitionCrcStruct partitionCrcStruct[4];
+} InterfaceCrcStruct;
+
+typedef struct {
+    SlotCrcStruct slotCrcStruct[16];
+} InputCrcStruct;
+
+#endif
diff --git a/tests/tegra/vic42.c b/tests/tegra/vic42.c
new file mode 100644
index 00000000..068b712a
--- /dev/null
+++ b/tests/tegra/vic42.c
@@ -0,0 +1,342 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#include <errno.h>
+#include <string.h>
+
+#include "private.h"
+#include "tegra.h"
+#include "vic.h"
+#include "vic42.h"
+
+struct vic42 {
+    struct vic base;
+
+    struct {
+        struct drm_tegra_mapping *map;
+        struct drm_tegra_bo *bo;
+    } config;
+
+    struct {
+        struct drm_tegra_mapping *map;
+        struct drm_tegra_bo *bo;
+    } filter;
+};
+
+static int vic42_fill(struct vic *v, struct vic_image *output,
+                      unsigned int left, unsigned int top,
+                      unsigned int right, unsigned int bottom,
+                      unsigned int alpha, unsigned int red,
+                      unsigned int green, unsigned int blue)
+{
+    struct vic42 *vic = container_of(v, struct vic42, base);
+    ConfigStruct *c;
+    int err;
+
+    err = drm_tegra_bo_map(vic->config.bo, (void **)&c);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    memset(c, 0, sizeof(*c));
+
+    c->outputConfig.TargetRectTop = top;
+    c->outputConfig.TargetRectLeft = left;
+    c->outputConfig.TargetRectRight = right;
+    c->outputConfig.TargetRectBottom = bottom;
+    c->outputConfig.BackgroundAlpha = alpha;
+    c->outputConfig.BackgroundR = red;
+    c->outputConfig.BackgroundG = green;
+    c->outputConfig.BackgroundB = blue;
+
+    c->outputSurfaceConfig.OutPixelFormat = output->format;
+    c->outputSurfaceConfig.OutBlkKind = output->kind;
+    c->outputSurfaceConfig.OutBlkHeight = 0;
+    c->outputSurfaceConfig.OutSurfaceWidth = output->width - 1;
+    c->outputSurfaceConfig.OutSurfaceHeight = output->height - 1;
+    c->outputSurfaceConfig.OutLumaWidth = output->stride - 1;
+    c->outputSurfaceConfig.OutLumaHeight = output->height - 1;
+    c->outputSurfaceConfig.OutChromaWidth = 16383;
+    c->outputSurfaceConfig.OutChromaHeight = 16383;
+
+    drm_tegra_bo_unmap(vic->config.bo);
+
+    return 0;
+}
+
+static int vic42_blit(struct vic *v, struct vic_image *output,
+                      struct vic_image *input)
+{
+    struct vic42 *vic = container_of(v, struct vic42, base);
+    SlotSurfaceConfig *surface;
+    SlotConfig *slot;
+    ConfigStruct *c;
+    int err;
+
+    err = drm_tegra_bo_map(vic->config.bo, (void **)&c);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    memset(c, 0, sizeof(*c));
+
+    c->outputConfig.TargetRectTop = 0;
+    c->outputConfig.TargetRectLeft = 0;
+    c->outputConfig.TargetRectRight = output->width - 1;
+    c->outputConfig.TargetRectBottom = output->height - 1;
+    c->outputConfig.BackgroundAlpha = 255;
+    c->outputConfig.BackgroundR = 1023;
+    c->outputConfig.BackgroundG = 1023;
+    c->outputConfig.BackgroundB = 1023;
+
+    c->outputSurfaceConfig.OutPixelFormat = output->format;
+    c->outputSurfaceConfig.OutBlkKind = output->kind;
+    c->outputSurfaceConfig.OutBlkHeight = 0;
+    c->outputSurfaceConfig.OutSurfaceWidth = output->width - 1;
+    c->outputSurfaceConfig.OutSurfaceHeight = output->height - 1;
+    c->outputSurfaceConfig.OutLumaWidth = output->stride - 1;
+    c->outputSurfaceConfig.OutLumaHeight = output->height - 1;
+    c->outputSurfaceConfig.OutChromaWidth = 16383;
+    c->outputSurfaceConfig.OutChromaHeight = 16383;
+
+    slot = &c->slotStruct[0].slotConfig;
+    slot->SlotEnable = 1;
+    slot->CurrentFieldEnable = 1;
+    slot->PlanarAlpha = 255;
+    slot->ConstantAlpha = 1;
+    slot->SourceRectLeft = 0 << 16;
+    slot->SourceRectRight = (input->width - 1) << 16;
+    slot->SourceRectTop = 0 << 16;
+    slot->SourceRectBottom = (input->height - 1) << 16;
+    slot->DestRectLeft = 0;
+    slot->DestRectRight = output->width - 1;
+    slot->DestRectTop = 0;
+    slot->DestRectBottom = output->height - 1;
+    slot->SoftClampHigh = 1023;
+
+    surface = &c->slotStruct[0].slotSurfaceConfig;
+    surface->SlotPixelFormat = input->format;
+    surface->SlotBlkKind = input->kind;
+    surface->SlotBlkHeight = 0; /* XXX */
+    surface->SlotCacheWidth = VIC_CACHE_WIDTH_64Bx4; /* XXX */
+    surface->SlotSurfaceWidth = input->width - 1;
+    surface->SlotSurfaceHeight = input->height - 1;
+    surface->SlotLumaWidth = input->stride - 1;
+    surface->SlotLumaHeight = input->height - 1;
+    surface->SlotChromaWidth = 16383;
+    surface->SlotChromaHeight = 16383;
+
+    drm_tegra_bo_unmap(vic->config.bo);
+
+    return 0;
+}
+
+static int vic42_flip(struct vic *v, struct vic_image *output,
+                      struct vic_image *input)
+{
+    struct vic42 *vic = container_of(v, struct vic42, base);
+    SlotSurfaceConfig *surface;
+    SlotConfig *slot;
+    ConfigStruct *c;
+    int err;
+
+    err = drm_tegra_bo_map(vic->config.bo, (void **)&c);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    memset(c, 0, sizeof(*c));
+
+    c->outputConfig.TargetRectTop = 0;
+    c->outputConfig.TargetRectLeft = 0;
+    c->outputConfig.TargetRectRight = output->width - 1;
+    c->outputConfig.TargetRectBottom = output->height - 1;
+    c->outputConfig.BackgroundAlpha = 255;
+    c->outputConfig.BackgroundR = 1023;
+    c->outputConfig.BackgroundG = 1023;
+    c->outputConfig.BackgroundB = 1023;
+    c->outputConfig.OutputFlipY = 1;
+
+    c->outputSurfaceConfig.OutPixelFormat = output->format;
+    c->outputSurfaceConfig.OutBlkKind = output->kind;
+    c->outputSurfaceConfig.OutBlkHeight = 0;
+    c->outputSurfaceConfig.OutSurfaceWidth = output->width - 1;
+    c->outputSurfaceConfig.OutSurfaceHeight = output->height - 1;
+    c->outputSurfaceConfig.OutLumaWidth = output->stride - 1;
+    c->outputSurfaceConfig.OutLumaHeight = output->height - 1;
+    c->outputSurfaceConfig.OutChromaWidth = 16383;
+    c->outputSurfaceConfig.OutChromaHeight = 16383;
+
+    slot = &c->slotStruct[0].slotConfig;
+    slot->SlotEnable = 1;
+    slot->CurrentFieldEnable = 1;
+    slot->PlanarAlpha = 255;
+    slot->ConstantAlpha = 1;
+    slot->SourceRectLeft = 0 << 16;
+    slot->SourceRectRight = (input->width - 1) << 16;
+    slot->SourceRectTop = 0 << 16;
+    slot->SourceRectBottom = (input->height - 1) << 16;
+    slot->DestRectLeft = 0;
+    slot->DestRectRight = output->width - 1;
+    slot->DestRectTop = 0;
+    slot->DestRectBottom = output->height - 1;
+    slot->SoftClampHigh = 1023;
+
+    surface = &c->slotStruct[0].slotSurfaceConfig;
+    surface->SlotPixelFormat = input->format;
+    surface->SlotBlkKind = input->kind;
+    surface->SlotBlkHeight = 0; /* XXX */
+    surface->SlotCacheWidth = VIC_CACHE_WIDTH_64Bx4; /* XXX */
+    surface->SlotSurfaceWidth = input->width - 1;
+    surface->SlotSurfaceHeight = input->height - 1;
+    surface->SlotLumaWidth = input->stride - 1;
+    surface->SlotLumaHeight = input->height - 1;
+    surface->SlotChromaWidth = 16383;
+    surface->SlotChromaHeight = 16383;
+
+    drm_tegra_bo_unmap(vic->config.bo);
+
+    return 0;
+}
+
+static int vic42_execute(struct vic *v, struct drm_tegra_pushbuf *pushbuf,
+                         uint32_t **ptrp, struct vic_image *output,
+                         struct vic_image **inputs, unsigned int num_inputs)
+{
+    struct vic42 *vic = container_of(v, struct vic42, base);
+    unsigned int i;
+
+    if (num_inputs > 1)
+        return -EINVAL;
+
+    VIC_PUSH_METHOD(pushbuf, ptrp, NVC5B6_VIDEO_COMPOSITOR_SET_APPLICATION_ID, 1);
+    VIC_PUSH_METHOD(pushbuf, ptrp, NVC5B6_VIDEO_COMPOSITOR_SET_CONTROL_PARAMS, (sizeof(ConfigStruct) / 16) << 16);
+    VIC_PUSH_BUFFER(pushbuf, ptrp, NVC5B6_VIDEO_COMPOSITOR_SET_CONFIG_STRUCT_OFFSET, vic->config.map, 0, 0);
+    VIC_PUSH_BUFFER(pushbuf, ptrp, NVC5B6_VIDEO_COMPOSITOR_SET_FILTER_STRUCT_OFFSET, vic->filter.map, 0, 0);
+    VIC_PUSH_BUFFER(pushbuf, ptrp, NVC5B6_VIDEO_COMPOSITOR_SET_OUTPUT_SURFACE_LUMA_OFFSET, output->map, 0, 0);
+
+    for (i = 0; i < num_inputs; i++) {
+        uint32_t method = NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE0_LUMA_OFFSET(0) + (i * 3) * 4;
+
+        VIC_PUSH_BUFFER(pushbuf, ptrp, method, inputs[i]->map, 0, 0);
+    }
+
+    VIC_PUSH_METHOD(pushbuf, ptrp, NVC5B6_VIDEO_COMPOSITOR_EXECUTE, 1 << 8);
+
+    return 0;
+}
+
+static void vic42_free(struct vic *v)
+{
+    struct vic42 *vic = container_of(v, struct vic42, base);
+
+    drm_tegra_channel_unmap(vic->filter.map);
+    drm_tegra_bo_unref(vic->filter.bo);
+
+    drm_tegra_channel_unmap(vic->config.map);
+    drm_tegra_bo_unref(vic->config.bo);
+
+    drm_tegra_syncpoint_free(v->syncpt);
+
+    free(vic);
+}
+
+static const struct vic_ops vic42_ops = {
+    .fill = vic42_fill,
+    .blit = vic42_blit,
+    .flip = vic42_flip,
+    .execute = vic42_execute,
+    .free = vic42_free,
+};
+
+int vic42_new(struct drm_tegra *drm, struct drm_tegra_channel *channel,
+              struct vic **vicp)
+{
+    struct vic42 *vic;
+    void *ptr;
+    int err;
+
+    vic = calloc(1, sizeof(*vic));
+    if (!vic)
+        return -ENOMEM;
+
+    vic->base.drm = drm;
+    vic->base.channel = channel;
+    vic->base.ops = &vic42_ops;
+    vic->base.version = 0x19;
+
+    err = drm_tegra_syncpoint_new(drm, &vic->base.syncpt);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate syncpoint: %s\n", strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_new(drm, 0, 16384, &vic->config.bo);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate configuration structurer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_channel_map(channel, vic->config.bo, DRM_TEGRA_CHANNEL_MAP_READ,
+                                &vic->config.map);
+    if (err < 0) {
+        fprintf(stderr, "failed to map configuration structure: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_new(drm, 0, 16384, &vic->filter.bo);
+    if (err < 0) {
+        fprintf(stderr, "failed to allocate filter buffer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    err = drm_tegra_bo_map(vic->filter.bo, &ptr);
+    if (err < 0) {
+        fprintf(stderr, "failed to map filter buffer: %s\n", strerror(-err));
+        return err;
+    }
+
+    memset(ptr, 0, 16384);
+    drm_tegra_bo_unmap(vic->filter.bo);
+
+    err = drm_tegra_channel_map(channel, vic->filter.bo, DRM_TEGRA_CHANNEL_MAP_READ,
+                                &vic->filter.map);
+    if (err < 0) {
+        fprintf(stderr, "failed to map filter buffer: %s\n",
+                strerror(-err));
+        return err;
+    }
+
+    if (vicp)
+        *vicp = &vic->base;
+
+    return 0;
+}
diff --git a/tests/tegra/vic42.h b/tests/tegra/vic42.h
new file mode 100644
index 00000000..3ed5cdbd
--- /dev/null
+++ b/tests/tegra/vic42.h
@@ -0,0 +1,597 @@
+/*
+ * Copyright © 2018 NVIDIA Corporation
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included in
+ * all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifndef VIC42_H
+#define VIC42_H
+
+#include <stdint.h>
+
+#define NVC5B6_VIDEO_COMPOSITOR_SET_APPLICATION_ID 0x00000200
+#define NVC5B6_VIDEO_COMPOSITOR_EXECUTE 0x00000300
+#define NVC5B6_VIDEO_COMPOSITOR_SET_CONTROL_PARAMS 0x00000704
+#define NVC5B6_VIDEO_COMPOSITOR_SET_CONFIG_STRUCT_OFFSET 0x00000708
+#define NVC5B6_VIDEO_COMPOSITOR_SET_FILTER_STRUCT_OFFSET 0x0000070c
+#define NVC5B6_VIDEO_COMPOSITOR_SET_HIST_OFFSET 0x00000714
+#define NVC5B6_VIDEO_COMPOSITOR_SET_OUTPUT_SURFACE_LUMA_OFFSET 0x00000720
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE0_LUMA_OFFSET(slot) (0x00001200 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE0_CHROMA_U_OFFSET(slot) (0x00001204 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE0_CHROMA_V_OFFSET(slot) (0x00001208 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE1_LUMA_OFFSET(slot) (0x0000120c + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE1_CHROMA_U_OFFSET(slot) (0x00001210 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE1_CHROMA_V_OFFSET(slot) (0x00001214 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE2_LUMA_OFFSET(slot) (0x00001218 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE2_CHROMA_U_OFFSET(slot) (0x0000121c + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE2_CHROMA_V_OFFSET(slot) (0x00001220 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE3_LUMA_OFFSET(slot) (0x00001224 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE3_CHROMA_U_OFFSET(slot) (0x00001228 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE3_CHROMA_V_OFFSET(slot) (0x0000122c + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE4_LUMA_OFFSET(slot) (0x00001230 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE4_CHROMA_U_OFFSET(slot) (0x00001234 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE4_CHROMA_V_OFFSET(slot) (0x00001238 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE5_LUMA_OFFSET(slot) (0x0000123c + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE5_CHROMA_U_OFFSET(slot) (0x00001240 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE5_CHROMA_V_OFFSET(slot) (0x00001244 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE6_LUMA_OFFSET(slot) (0x00001248 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE6_CHROMA_U_OFFSET(slot) (0x0000124c + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE6_CHROMA_V_OFFSET(slot) (0x00001250 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE7_LUMA_OFFSET(slot) (0x00001254 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE7_CHROMA_U_OFFSET(slot) (0x00001258 + (slot) * 0x00000060)
+#define NVC5B6_VIDEO_COMPOSITOR_SET_SURFACE7_CHROMA_V_OFFSET(slot) (0x0000125c + (slot) * 0x00000060)
+
+typedef struct {
+    uint64_t SlotEnable : 1; /* 0 */
+    uint64_t DeNoise : 1; /* 1 */
+    uint64_t AdvancedDenoise : 1; /* 2 */
+    uint64_t CadenceDetect : 1; /* 3 */
+    uint64_t MotionMap : 1; /* 4 */
+    uint64_t MMapCombine : 1; /* 5 */
+    uint64_t IsEven : 1; /* 6 */
+    uint64_t ChromaEven : 1; /* 7 */
+    uint64_t CurrentFieldEnable : 1; /* 8 */
+    uint64_t PrevFieldEnable : 1; /* 9 */
+    uint64_t NextFieldEnable : 1; /* 10 */
+    uint64_t NextNrFieldEnable : 1; /* 11 */
+    uint64_t CurMotionFieldEnable : 1; /* 12 */
+    uint64_t PrevMotionFieldEnable : 1; /* 13 */
+    uint64_t PpMotionFieldEnable : 1; /* 14 */
+    uint64_t CombMotionFieldEnable : 1; /* 15 */
+    uint64_t FrameFormat : 4; /* 19..16 */
+    uint64_t FilterLengthY : 2; /* 21..20 */
+    uint64_t FilterLengthX : 2; /* 23..22 */
+    uint64_t Panoramic : 12; /* 35..24 */
+    uint64_t ChromaUpLengthY : 2; /* 37..36 */
+    uint64_t ChromaUpLengthX : 2; /* 39..38 */
+    uint64_t reserved1 : 18; /* 57..40 */
+    uint64_t DetailFltClamp : 6; /* 63..58 */
+    uint64_t FilterNoise : 10; /* 73..64 */
+    uint64_t FilterDetail : 10; /* 83..74 */
+    uint64_t ChromaNoise : 10; /* 93..84 */
+    uint64_t ChromaDetail : 10; /* 103..94 */
+    uint64_t DeinterlaceMode : 4; /* 107..104 */
+    uint64_t MotionAccumWeight : 3; /* 110..108 */
+    uint64_t NoiseIir : 11; /* 121..111 */
+    uint64_t LightLevel : 4; /* 125..122 */
+    uint64_t reserved4 : 2; /* 127..126 */
+    /* 128 */
+    uint64_t SoftClampLow : 10; /* 9..0 */
+    uint64_t SoftClampHigh : 10; /* 19..10 */
+    uint64_t reserved5 : 12; /* 31..20 */
+    uint64_t reserved6 : 2; /* 33..32 */
+    uint64_t PlanarAlpha : 8; /* 41..34 */
+    uint64_t ConstantAlpha : 1; /* 42 */
+    uint64_t StereoInterleave : 3; /* 45..43 */
+    uint64_t ClipEnabled : 1; /* 46 */
+    uint64_t ClearRectMask : 8; /* 54..47 */
+    uint64_t DegammaMode : 2; /* 56..55 */
+    uint64_t reserved7 : 1; /* 57 */
+    uint64_t DecompressEnable : 1; /* 58 */
+    uint64_t DecompressKind : 4; /* 62..59 */
+    uint64_t reserved9 : 1; /* 63 */
+    uint64_t DecompressCtbCount : 8; /* 71..64 */
+    uint64_t DecompressZbcColor : 32; /* 103..72 */
+    uint64_t reserved12 : 24; /* 127..104 */
+    /* 256 */
+    uint64_t SourceRectLeft : 30; /* 29..0 */
+    uint64_t reserved14 : 2; /* 31..30 */
+    uint64_t SourceRectRight : 30; /* 61..32 */
+    uint64_t reserved15 : 2; /* 63..62 */
+    uint64_t SourceRectTop : 30; /* 93..64 */
+    uint64_t reserved16 : 2; /* 95..94 */
+    uint64_t SourceRectBottom : 30; /* 125..96 */
+    uint64_t reserved17 : 2; /* 127..126 */
+    /* 384 */
+    uint64_t DestRectLeft : 14; /* 13..0 */
+    uint64_t reserved18 : 2; /* 15..14 */
+    uint64_t DestRectRight : 14; /* 29..16 */
+    uint64_t reserved19 : 2; /* 31..30 */
+    uint64_t DestRectTop : 14; /* 45..32 */
+    uint64_t reserved20 : 2; /* 47..46 */
+    uint64_t DestRectBottom : 14; /* 61..48 */
+    uint64_t reserved21 : 2; /* 63..62 */
+    uint64_t B16ScalerEnable : 1; /* 64 */
+    uint64_t reserved22 : 31; /* 95..65 */
+    uint64_t reserved23 : 32; /* 127..96 */
+} SlotConfig;
+
+typedef struct {
+    uint64_t SlotPixelFormat : 7; /* 6..0 */
+    uint64_t SlotChromaLocHORIZ : 2; /* 8..7 */
+    uint64_t SlotChromaLocVert : 2; /* 10..9 */
+    uint64_t SlotBlkKind : 4; /* 14..11 */
+    uint64_t SlotBlkHeight : 4; /* 18..15 */
+    uint64_t SlotCacheWidth : 3; /* 21..19 */
+    uint64_t reserved0 : 10; /* 31..22 */
+    uint64_t SlotSurfaceWidth : 14; /* 45..32 */
+    uint64_t SlotSurfaceHeight : 14; /* 59..46 */
+    uint64_t reserved1 : 4; /* 63..60 */
+    uint64_t SlotLumaWidth : 14; /* 77..64 */
+    uint64_t SlotLumaHeight : 14; /* 91..78 */
+    uint64_t reserved2 : 4; /* 95..92 */
+    uint64_t SlotChromaWidth : 14; /* 109..96 */
+    uint64_t SlotChromaHeight : 14; /* 123..110 */
+    uint64_t reserved3 : 4; /* 127..124 */
+} SlotSurfaceConfig;
+
+typedef struct {
+    uint64_t luma_coeff0 : 20; /* 19..0 */
+    uint64_t luma_coeff1 : 20; /* 39..20 */
+    uint64_t luma_coeff2 : 20; /* 59..40 */
+    uint64_t luma_r_shift : 4; /* 63..60 */
+    uint64_t luma_coeff3 : 20; /* 83..64 */
+    uint64_t LumaKeyLower : 10; /* 93..84 */
+    uint64_t LumaKeyUpper : 10; /* 103..94 */
+    uint64_t LumaKeyEnabled : 1; /* 104 */
+    uint64_t reserved0 : 2; /* 106..105 */
+    uint64_t reserved1 : 21; /* 127..107 */
+} LumaKeyStruct;
+
+typedef struct {
+    uint64_t matrix_coeff00 : 20; /* 19..0 */
+    uint64_t matrix_coeff10 : 20; /* 39..20 */
+    uint64_t matrix_coeff20 : 20; /* 59..40 */
+    uint64_t matrix_r_shift : 4; /* 63..60 */
+    uint64_t matrix_coeff01 : 20; /* 83..64 */
+    uint64_t matrix_coeff11 : 20; /* 103..84 */
+    uint64_t matrix_coeff21 : 20; /* 123..104 */
+    uint64_t reserved0 : 3; /* 126..124 */
+    uint64_t matrix_enable : 1; /* 127 */
+    /* 128 */
+    uint64_t matrix_coeff02 : 20; /* 19..0 */
+    uint64_t matrix_coeff12 : 20; /* 39..20 */
+    uint64_t matrix_coeff22 : 20; /* 59..40 */
+    uint64_t reserved1 : 4; /* 63..60 */
+    uint64_t matrix_coeff03 : 20; /* 83..64 */
+    uint64_t matrix_coeff13 : 20; /* 103..84 */
+    uint64_t matrix_coeff23 : 20; /* 123..104 */
+    uint64_t reserved2 : 4; /* 127..124 */
+} MatrixStruct;
+
+typedef struct {
+    uint64_t ClearRect0Left : 14; /* 13..0 */
+    uint64_t reserved0 : 2; /* 15..14 */
+    uint64_t ClearRect0Right : 14; /* 29..16 */
+    uint64_t reserved1 : 2; /* 31..30 */
+    uint64_t ClearRect0Top : 14; /* 45..32 */
+    uint64_t reserved2 : 2; /* 47..46 */
+    uint64_t ClearRect0Bottom : 14; /* 61..48 */
+    uint64_t reserved3 : 2; /* 63..62 */
+    uint64_t ClearRect1Left : 14; /* 77..64 */
+    uint64_t reserved4 : 2; /* 79..78 */
+    uint64_t ClearRect1Right : 14; /* 93..80 */
+    uint64_t reserved5 : 2; /* 95..94 */
+    uint64_t ClearRect1Top : 14; /* 109..96 */
+    uint64_t reserved6 : 2; /* 111..110 */
+    uint64_t ClearRect1Bottom : 14; /* 125..112 */
+    uint64_t reserved7 : 2; /* 127..126 */
+} ClearRectStruct;
+
+typedef struct {
+    uint64_t reserved0 : 2; /* 1..0 */
+    uint64_t AlphaK1 : 8; /* 9..2 */
+    uint64_t reserved1 : 6; /* 17..10 */
+    uint64_t AlphaK2 : 8; /* 25..18 */
+    uint64_t reserved2 : 6; /* 31..26 */
+    uint64_t SrcFactCMatchSelect : 3; /* 34..32 */
+    uint64_t reserved3 : 1; /* 35 */
+    uint64_t DstFactCMatchSelect : 3; /* 38..36 */
+    uint64_t reserved4 : 1; /* 39 */
+    uint64_t SrcFactAMatchSelect : 3; /* 42..40 */
+    uint64_t reserved5 : 1; /* 43 */
+    uint64_t DstFactAMatchSelect : 3; /* 46..44 */
+    uint64_t reserved6 : 1; /* 47 */
+    uint64_t reserved7 : 4; /* 51..48 */
+    uint64_t reserved8 : 4; /* 55..52 */
+    uint64_t reserved9 : 4; /* 59..56 */
+    uint64_t reserved10 : 4; /* 63..60 */
+    uint64_t reserved11 : 2; /* 65..64 */
+    uint64_t OverrideR : 10; /* 75..66 */
+    uint64_t OverrideG : 10; /* 85..76 */
+    uint64_t OverrideB : 10; /* 95..86 */
+    uint64_t reserved12 : 2; /* 97..96 */
+    uint64_t OverrideA : 8; /* 105..98 */
+    uint64_t reserved13 : 2; /* 107..106 */
+    uint64_t UseOverrideR : 1; /* 108 */
+    uint64_t UseOverrideG : 1; /* 109 */
+    uint64_t UseOverrideB : 1; /* 110 */
+    uint64_t UseOverrideA : 1; /* 111 */
+    uint64_t MaskR : 1; /* 112 */
+    uint64_t MaskG : 1; /* 113 */
+    uint64_t MaskB : 1; /* 114 */
+    uint64_t MaskA : 1; /* 115 */
+    uint64_t reserved14 : 12; /* 127..116 */
+} BlendingSlotStruct;
+
+typedef struct {
+    uint64_t AlphaFillMode : 3; /* 2..0 */
+    uint64_t AlphaFillSlot : 3; /* 5..3 */
+    uint64_t reserved0 : 2; /* 6..5 */
+    uint64_t BackgroundAlpha : 8; /* 15..7 */
+    uint64_t BackgroundR : 10; /* 25..16 */
+    uint64_t BackgroundG : 10; /* 35..26 */
+    uint64_t BackgroundB : 10; /* 45..36 */
+    uint64_t RegammaMode : 2; /* 47..46 */
+    uint64_t OutputFlipX : 1; /* 48 */
+    uint64_t OutputFlipY : 1; /* 49 */
+    uint64_t OutputTranspose : 1; /* 50 */
+    uint64_t reserved1 : 1; /* 51 */
+    uint64_t reserved2 : 12; /* 63..52 */
+    uint64_t TargetRectLeft : 14; /* 77..64 */
+    uint64_t reserved3 : 2; /* 79..78 */
+    uint64_t TargetRectRight : 14; /* 93..80 */
+    uint64_t reserved4 : 2; /* 95..94 */
+    uint64_t TargetRectTop : 14; /* 109..96 */
+    uint64_t reserved5 : 2; /* 111..110 */
+    uint64_t TargetRectBottom : 14; /* 125..112 */
+    uint64_t reserved6 : 2; /* 127..126 */
+} OutputConfig;
+
+typedef struct {
+    uint64_t OutPixelFormat : 7; /* 6..0 */
+    uint64_t OutChromaLocHoriz : 2; /* 8..7 */
+    uint64_t OutChromaLocVert : 2; /* 10..9 */
+    uint64_t OutBlkKind : 4; /* 14..11 */
+    uint64_t OutBlkHeight : 4; /* 18..15 */
+    uint64_t reserved0 : 3; /* 21..19 */
+    uint64_t reserved1 : 10; /* 31..22 */
+    uint64_t OutSurfaceWidth : 14; /* 45..32 */
+    uint64_t OutSurfaceHeight : 14; /* 59..46 */
+    uint64_t reserved2 : 4; /* 63..60 */
+    uint64_t OutLumaWidth : 14; /* 77..64 */
+    uint64_t OutLumaHeight : 14; /* 91..78 */
+    uint64_t reserved3 : 4; /* 95..92 */
+    uint64_t OutChromaWidth : 14; /* 109..96 */
+    uint64_t OutChromaHeight : 14; /* 123..110 */
+    uint64_t reserved4 : 4; /* 127..124 */
+} OutputSurfaceConfig;
+
+typedef struct {
+    uint64_t f00 : 10; /* 9..0 */
+    uint64_t f10 : 10; /* 19..10 */
+    uint64_t f20 : 10; /* 29..20 */
+    uint64_t reserved0 : 2; /* 31..30 */
+    uint64_t f01 : 10; /* 41..32 */
+    uint64_t f11 : 10; /* 51..42 */
+    uint64_t f21 : 10; /* 61..52 */
+    uint64_t reserved1 : 2; /* 63..62 */
+    uint64_t f02 : 10; /* 73..64 */
+    uint64_t f12 : 10; /* 83..74 */
+    uint64_t f22 : 10; /* 93..84 */
+    uint64_t reserved2 : 2; /* 95..94 */
+    uint64_t f03 : 10; /* 105..96 */
+    uint64_t f13 : 10; /* 115..106 */
+    uint64_t f23 : 10; /* 125..116 */
+    uint64_t reserved3 : 2; /* 127..126 */
+} FilterCoeffStruct;
+
+typedef struct {
+    uint64_t DownsampleHoriz : 11; /* 10..0 */
+    uint64_t reserved0 : 5; /* 15..11 */
+    uint64_t DownsampleVert : 11; /* 26..16 */
+    uint64_t reserved1 : 5; /* 31..27 */
+    uint64_t reserved2 : 32; /* 63..32 */
+    uint64_t reserved3 : 32; /* 95..64 */
+    uint64_t reserved4 : 32; /* 127..96 */
+} PipeConfig;
+
+typedef struct {
+    uint64_t OldCadence : 32; /* 31..0 */
+    uint64_t OldDiff : 32; /* 63..32 */
+    uint64_t OldWeave : 32; /* 95..64 */
+    uint64_t OlderWeave : 32; /* 127..96 */
+} SlotHistoryBuffer;
+
+typedef struct {
+    uint64_t crc0 : 32; /* 31..0 */
+    uint64_t crc1 : 32; /* 63..32 */
+    uint64_t crc2 : 32; /* 95..64 */
+    uint64_t crc3 : 32; /* 127..96 */
+} PartitionCrcStruct;
+
+typedef struct {
+    uint64_t crc0 : 32; /* 31..0 */
+    uint64_t crc1 : 32; /* 63..32 */
+} SlotCrcStruct;
+
+typedef struct {
+    uint64_t ErrorStatus : 32; /* 31..0 */
+    uint64_t CycleCount : 32; /* 63..32 */
+    uint64_t reserved0 : 32; /* 95..64 */
+    uint64_t reserved1 : 32; /* 127..96 */
+} StatusStruct;
+
+typedef struct {
+    uint64_t coeff_0 : 10; /* 9..0 */
+    uint64_t reserved0 : 6; /* 15..10 */
+    uint64_t coeff_1 : 10; /* 25..16 */
+    uint64_t reserved1 : 6; /* 31..26 */
+    uint64_t coeff_2 : 10; /* 41..32 */
+    uint64_t reserved2 : 6; /* 47..42 */
+    uint64_t coeff_3 : 10; /* 57..48 */
+    uint64_t reserved3 : 6; /* 63..58 */
+} CoeffPhaseParamStruct;
+
+typedef struct {
+    uint64_t GeoTranEn : 1; /* 0 */
+    uint64_t GeoTranMode : 2; /* 2..1 */
+    uint64_t IPTMode : 1; /* 3 */
+    uint64_t PixelFilterType : 2; /* 5..4 */
+    uint64_t PixelFormat : 7; /* 12..6 */
+    uint64_t CacheWidth : 3; /* 15..13 */
+    uint64_t SrcBlkKind : 4; /* 19..16 */
+    uint64_t SrcBlkHeight : 4; /* 23..20 */
+    uint64_t DestBlkKind : 4; /* 27..24 */
+    uint64_t DestBlkHeight : 4; /* 31..28 */
+    uint64_t MskBitMapEn : 1; /* 32 */
+    uint64_t MaskedPixelFillMode : 1; /* 33 */
+    uint64_t XSobelMode : 2; /* 35..34 */
+    uint64_t SubFrameEn : 1; /* 36 */
+    uint64_t reserved0 : 3; /* 39..37 */
+    uint64_t XSobelBlkKind : 4; /* 43..40 */
+    uint64_t XSobelBlkHeight : 4; /* 47..44 */
+    uint64_t XSobelDSBlkKind : 4; /* 51..48 */
+    uint64_t XSobelDSBlkHeight : 4; /* 55..52 */
+    uint64_t reserved1 : 8; /* 63..56 */
+    uint64_t NonFixedPatchEn : 1; /* 64 */
+    uint64_t HorRegionNum : 2; /* 66..65 */
+    uint64_t VerRegionNum : 2; /* 68..67 */
+    uint64_t reserved2 : 3; /* 71..69 */
+    uint64_t log2HorSpace_0 : 3; /* 74..72 */
+    uint64_t log2VerSpace_0 : 3; /* 77..75 */
+    uint64_t log2HorSpace_1 : 3; /* 80..78 */
+    uint64_t log2VerSpace_1 : 3; /* 83..81 */
+    uint64_t log2HorSpace_2 : 3; /* 86..84 */
+    uint64_t log2VerSpace_2 : 3; /* 89..87 */
+    uint64_t log2HorSpace_3 : 3; /* 92..90 */
+    uint64_t log2VerSpace_3 : 3; /* 95..93 */
+    uint64_t horRegionWidth_0 : 14; /* 109..96 */
+    uint64_t reserved3 : 2; /* 111..110 */
+    uint64_t horRegionWidth_1 : 14; /* 125..112 */
+    uint64_t reserved4 : 2; /* 127..126 */
+    uint64_t horRegionWidth_2 : 14; /* 141..128 */
+    uint64_t reserved5 : 2; /* 143..142 */
+    uint64_t horRegionWidth_3 : 14; /* 157..144 */
+    uint64_t reserved6 : 2; /* 159..158 */
+    uint64_t verRegionHeight_0 : 14; /* 173..160 */
+    uint64_t reserved7 : 2; /* 175..174 */
+    uint64_t verRegionHeight_1 : 14; /* 189..176 */
+    uint64_t reserved8 : 2; /* 191..190 */
+    uint64_t verRegionHeight_2 : 14; /* 205..192 */
+    uint64_t reserved9 : 2; /* 207..206 */
+    uint64_t verRegionHeight_3 : 14; /* 221..208 */
+    uint64_t reserved10 : 2; /* 223..222 */
+    uint64_t IPT_M11 : 32; /* 255..224 */
+    uint64_t IPT_M12 : 32; /* 287..256 */
+    uint64_t IPT_M13 : 32; /* 319..288 */
+    uint64_t IPT_M21 : 32; /* 351..320 */
+    uint64_t IPT_M22 : 32; /* 383..352 */
+    uint64_t IPT_M23 : 32; /* 415..384 */
+    uint64_t IPT_M31 : 32; /* 447..416 */
+    uint64_t IPT_M32 : 32; /* 479..448 */
+    uint64_t IPT_M33 : 32; /* 511..480 */
+    uint64_t SourceRectLeft : 14; /* 525..512 */
+    uint64_t reserved11 : 2; /* 527..526 */
+    uint64_t SourceRectRight : 14; /* 541..528 */
+    uint64_t reserved12 : 2; /* 543..542 */
+    uint64_t SourceRectTop : 14; /* 557..544 */
+    uint64_t reserved13 : 2; /* 559..558 */
+    uint64_t SourceRectBottom : 14; /* 573..560 */
+    uint64_t reserved14; /* 575..574 */
+    uint64_t SrcImgWidth : 14; /* 589..576 */
+    uint64_t reserved15 : 2; /* 591..590 */
+    uint64_t SrcImgHeight : 14; /* 605..592 */
+    uint64_t reserved16 : 2; /* 607..606 */
+    uint64_t SrcSfcLumaWidth : 14; /* 621..608 */
+    uint64_t reserved17 : 2; /* 623..622 */
+    uint64_t SrcSfcLumaHeight : 14; /* 637..624 */
+    uint64_t reserved18 : 2; /* 639..638 */
+    uint64_t SrcSfcChromaWidth : 14; /* 653..640 */
+    uint64_t reserved19 : 2; /* 655..654 */
+    uint64_t SrcSfcChromaHeight : 14; /* 669..656 */
+    uint64_t reserved20 : 2; /* 671..670 */
+    uint64_t DestRectLeft : 14; /* 685..672 */
+    uint64_t reserved21 : 2; /* 687..686 */
+    uint64_t DestRectRight : 14; /* 701..688 */
+    uint64_t reserved22 : 2; /* 703..702 */
+    uint64_t DestRectTop : 14; /* 717..704 */
+    uint64_t reserved23 : 2; /* 719..718 */
+    uint64_t DestRectBottom : 14; /* 733..720 */
+    uint64_t reserved24 : 2; /* 735..734 */
+    uint64_t SubFrameRectTop : 14; /* 749..736 */
+    uint64_t reserved25 : 2; /* 751..750 */
+    uint64_t SubFrameRectBottom : 14; /* 765..752 */
+    uint64_t reserved26 : 2; /* 767..766 */
+    uint64_t DestSfcLumaWidth : 14; /* 781..768 */
+    uint64_t reserved27 : 2; /* 783..782 */
+    uint64_t DestSfcLumaHeight : 14; /* 797..784 */
+    uint64_t reserved28 : 2; /* 799..798 */
+    uint64_t DestSfcChromaWidth : 14; /* 813..800 */
+    uint64_t reserved29 : 2; /* 815..814 */
+    uint64_t DestSfcChromaHeight : 14; /* 829..816 */
+    uint64_t reserved30 : 2; /* 831..830 */
+    uint64_t SparseWarpMapWidth : 14; /* 845..832 */
+    uint64_t reserved31 : 2; /* 847..846 */
+    uint64_t SparseWarpMapHeight : 14; /* 861..848 */
+    uint64_t reserved32 : 2; /* 863..862 */
+    uint64_t SparseWarpMapStride : 14; /* 877..864 */
+    uint64_t reserved33 : 2; /* 879..878 */
+    uint64_t MaskBitMapWidth : 14; /* 893..880 */
+    uint64_t reserved34 : 2; /* 895..894 */
+    uint64_t MaskBitMapHeight : 14; /* 909..896 */
+    uint64_t reserved35 : 2; /* 911..910 */
+    uint64_t MaskBitMapStride : 14; /* 925..912 */
+    uint64_t reserved36 : 2; /* 927..926 */
+    uint64_t XSobelWidth : 14; /* 941..928 */
+    uint64_t reserved37 : 2; /* 943..942 */
+    uint64_t XSobelHeight : 14; /* 957..944 */
+    uint64_t reserved38 : 2; /* 959..958 */
+    uint64_t XSobelStride : 14; /* 973..960 */
+    uint64_t reserved39 : 2; /* 975..974 */
+    uint64_t DSStride : 14; /* 989..976 */
+    uint64_t reserved40 : 2; /* 991..990 */
+    uint64_t XSobelTopOffset : 32; /* 1023..992 */
+    uint64_t reserved41 : 32; /* 1055..1024 */
+    uint64_t maskY : 16; /* 1071..1056 */
+    uint64_t maskU : 16; /* 1087..1072 */
+    uint64_t maskV : 16; /* 1103..1088 */
+    uint64_t reserved42 : 16; /* 1119..1104 */
+} GeoTranConfigParamStruct;
+
+typedef struct {
+    uint64_t TNR3En : 1; /* 0 */
+    uint64_t BetaBlendingEn : 1; /* 1 */
+    uint64_t AlphaBlendingEn : 1; /* 2 */
+    uint64_t AlphaSmoothEn : 1; /* 3 */
+    uint64_t TempAlphaRestrictEn : 1; /* 4 */
+    uint64_t AlphaClipEn : 1; /* 5 */
+    uint64_t BFRangeEn : 1; /* 6 */
+    uint64_t BFDomainEn : 1; /* 7 */
+    uint64_t BFRangeLumaShift : 4; /* 11..8 */
+    uint64_t BFRangeChromaShift : 4; /* 15..12 */
+    uint64_t SADMultiplier : 6; /* 21..16 */
+    uint64_t reserved1 : 2; /* 23..22 */
+    uint64_t SADWeightLuma : 6; /* 29..24 */
+    uint64_t reserved2 : 2; /* 31..30 */
+    uint64_t TempAlphaRestrictIncCap : 11; /* 42..32 */
+    uint64_t reserved3 : 5; /* 47..43 */
+    uint64_t AlphaScaleIIR : 11; /* 58..48 */
+    uint64_t reserved4 : 5; /* 63..59 */
+    uint64_t AlphaClipMaxLuma : 11; /* 74..64 */
+    uint64_t reserved5 : 5; /* 79..75 */
+    uint64_t AlphaClipMinLuma : 11; /* 90..80 */
+    uint64_t reserved6 : 5; /* 95..91 */
+    uint64_t AlphaClipMaxChroma : 11; /* 106..96 */
+    uint64_t reserved7 : 5; /* 111..107 */
+    uint64_t AlphaClipMinChroma : 11; /* 122..112 */
+    uint64_t reserved8 : 5; /* 127..123 */
+    uint64_t BetaCalcMaxBeta : 11; /* 138..128 */
+    uint64_t reserved9 : 5; /* 143..139 */
+    uint64_t BetaCalcMinBeta : 11; /* 154..144 */
+    uint64_t reserved10 : 5; /* 159..155 */
+    uint64_t BetaCalcBetaX1 : 11; /* 170..160 */
+    uint64_t reserved11 : 5; /* 175..171 */
+    uint64_t BetaCalcBetaX2 : 11; /* 186..176 */
+    uint64_t reserved12 : 5; /* 191..187 */
+    uint64_t BetaCalcStepBeta : 11; /* 202..192 */
+    uint64_t reserved13 : 5; /* 207..203 */
+    uint64_t reserved14 : 16; /* 223..208 */
+    uint64_t BFDomainLumaCoeffC00 : 7; /* 230..224 */
+    uint64_t reserved15 : 1; /* 231 */
+    uint64_t BFDomainLumaCoeffC01 : 7; /* 238..232 */
+    uint64_t reserved16 : 1; /* 239 */
+    uint64_t BFDomainLumaCoeffC02 : 7; /* 246..240 */
+    uint64_t reserved17 : 1; /* 247 */
+    uint64_t BFDomainLumaCoeffC11 : 7; /* 254..248 */
+    uint64_t reserved18 : 1; /* 255 */
+    uint64_t BFDomainLumaCoeffC12 : 7; /* 262..256 */
+    uint64_t reserved19 : 1; /* 263 */
+    uint64_t BFDomainLumaCoeffC22 : 7; /* 270..264 */
+    uint64_t reserved20 : 1; /* 271 */
+    uint64_t reserved21 : 16; /* 287..272 */
+    uint64_t BFDomainChromaCoeffC00 : 7; /* 294..288 */
+    uint64_t reserved22 : 1; /* 295 */
+    uint64_t BFDomainChromaCoeffC01 : 7; /* 302..296 */
+    uint64_t reserved23 : 1; /* 303 */
+    uint64_t BFDomainChromaCoeffC02 : 7; /* 310..304 */
+    uint64_t reserved24 : 1; /* 311 */
+    uint64_t BFDomainChromaCoeffC11 : 7; /* 318..312 */
+    uint64_t reserved25 : 1; /* 319 */
+    uint64_t BFDomainChromaCoeffC12 : 7; /* 326..320 */
+    uint64_t reserved26 : 1; /* 327 */
+    uint64_t BFDomainChromaCoeffC22 : 7; /* 334..328 */
+    uint64_t reserved27 : 1; /* 335 */
+    uint64_t reserved28 : 16; /* 351..336 */
+    uint64_t LeftBufSize : 32; /* 383..352 */
+    uint64_t TopBufSize : 32; /* 415..384 */
+    uint64_t AlphaSufStride : 14; /* 429..416 */
+    uint64_t reserved29 : 18; /* 447..430 */
+} TNR3ConfigParamStruct;
+
+typedef struct {
+    uint64_t item0 : 7; /* 6..0 */
+    uint64_t reserved0 : 9; /* 15..7 */
+    uint64_t item1 : 7; /* 22..16 */
+    uint64_t reserved1 : 9; /* 31..23 */
+    uint64_t item2 : 7; /* 38..32 */
+    uint64_t reserved2 : 9; /* 47..39 */
+    uint64_t item3 : 7; /* 54..48 */
+    uint64_t reserved3 : 9; /* 63..55 */
+} BFRangeTableItems;
+
+typedef struct {
+    SlotConfig slotConfig;
+    SlotSurfaceConfig slotSurfaceConfig;
+    LumaKeyStruct lumaKeyStruct;
+    MatrixStruct colorMatrixStruct;
+    MatrixStruct gamutMatrixStruct;
+    BlendingSlotStruct blendingSlotStruct;
+} SlotStruct;
+
+typedef struct {
+    FilterCoeffStruct filterCoeffStruct[520];
+} FilterStruct;
+
+typedef struct {
+    PipeConfig pipeConfig;
+    OutputConfig outputConfig;
+    OutputSurfaceConfig outputSurfaceConfig;
+    MatrixStruct outColorMatrixStruct;
+    ClearRectStruct clearRectStruct[4];
+    SlotStruct slotStruct[16];
+} ConfigStruct;
+
+typedef struct {
+    PartitionCrcStruct partitionCrcStruct[2];
+} InterfaceCrcStruct;
+
+typedef struct {
+    SlotCrcStruct slotCrcStruct[16];
+} InputCrcStruct;
+
+typedef struct {
+    GeoTranConfigParamStruct paramConfig;
+    CoeffPhaseParamStruct FilterCoeff[17];
+    TNR3ConfigParamStruct tnr3Config;
+    BFRangeTableItems BFRangeTableLuma[16];
+    BFRangeTableItems BFRangeTableChroma[16];
+} GeoTranConfigStruct;
+
+#endif
diff --git a/tests/util/Makefile.sources b/tests/util/Makefile.sources
deleted file mode 100644
index e5f85113..00000000
--- a/tests/util/Makefile.sources
+++ /dev/null
@@ -1,8 +0,0 @@
-UTIL_FILES := \
-	common.h \
-	format.c \
-	format.h \
-	kms.c \
-	kms.h \
-	pattern.c \
-	pattern.h
diff --git a/tests/util/format.c b/tests/util/format.c
index 1ca1b82c..eda3c671 100644
--- a/tests/util/format.c
+++ b/tests/util/format.c
@@ -40,7 +40,10 @@
 
 static const struct util_format_info format_info[] = {
 	/* Indexed */
-	{ DRM_FORMAT_C8, "C8" },
+	{ DRM_FORMAT_C1, "C1", .ncolors = 2 },
+	{ DRM_FORMAT_C2, "C2", .ncolors = 4 },
+	{ DRM_FORMAT_C4, "C4", .ncolors = 16 },
+	{ DRM_FORMAT_C8, "C8", .ncolors = 256 },
 	/* YUV packed */
 	{ DRM_FORMAT_UYVY, "UYVY", MAKE_YUV_INFO(YUV_YCbCr | YUV_CY, 2, 2, 2) },
 	{ DRM_FORMAT_VYUY, "VYUY", MAKE_YUV_INFO(YUV_YCrCb | YUV_CY, 2, 2, 2) },
@@ -51,6 +54,11 @@ static const struct util_format_info format_info[] = {
 	{ DRM_FORMAT_NV21, "NV21", MAKE_YUV_INFO(YUV_YCrCb, 2, 2, 2) },
 	{ DRM_FORMAT_NV16, "NV16", MAKE_YUV_INFO(YUV_YCbCr, 2, 1, 2) },
 	{ DRM_FORMAT_NV61, "NV61", MAKE_YUV_INFO(YUV_YCrCb, 2, 1, 2) },
+	{ DRM_FORMAT_NV24, "NV24", MAKE_YUV_INFO(YUV_YCbCr, 1, 1, 2) },
+	{ DRM_FORMAT_NV42, "NV42", MAKE_YUV_INFO(YUV_YCrCb, 1, 1, 2) },
+	{ DRM_FORMAT_NV15, "NV15", MAKE_YUV_INFO(YUV_YCbCr, 2, 2, 2) },
+	{ DRM_FORMAT_NV20, "NV20", MAKE_YUV_INFO(YUV_YCbCr, 2, 1, 2) },
+	{ DRM_FORMAT_NV30, "NV30", MAKE_YUV_INFO(YUV_YCbCr, 1, 1, 2) },
 	/* YUV planar */
 	{ DRM_FORMAT_YUV420, "YU12", MAKE_YUV_INFO(YUV_YCbCr, 2, 2, 1) },
 	{ DRM_FORMAT_YVU420, "YV12", MAKE_YUV_INFO(YUV_YCrCb, 2, 2, 1) },
@@ -73,6 +81,9 @@ static const struct util_format_info format_info[] = {
 	{ DRM_FORMAT_BGRX5551, "BX15", MAKE_RGB_INFO(5, 1, 5, 6, 5, 11, 0, 0) },
 	{ DRM_FORMAT_RGB565, "RG16", MAKE_RGB_INFO(5, 11, 6, 5, 5, 0, 0, 0) },
 	{ DRM_FORMAT_BGR565, "BG16", MAKE_RGB_INFO(5, 0, 6, 5, 5, 11, 0, 0) },
+	/* Big-endian RGB16 */
+	{ DRM_FORMAT_XRGB1555 | DRM_FORMAT_BIG_ENDIAN, "XR15_BE", MAKE_RGB_INFO(5, 10, 5, 5, 5, 0, 0, 0) },
+	{ DRM_FORMAT_RGB565 | DRM_FORMAT_BIG_ENDIAN, "RG16_BE", MAKE_RGB_INFO(5, 11, 6, 5, 5, 0, 0, 0) },
 	/* RGB24 */
 	{ DRM_FORMAT_BGR888, "BG24", MAKE_RGB_INFO(8, 0, 8, 8, 8, 16, 0, 0) },
 	{ DRM_FORMAT_RGB888, "RG24", MAKE_RGB_INFO(8, 16, 8, 8, 8, 0, 0, 0) },
diff --git a/tests/util/format.h b/tests/util/format.h
index 2ce1c021..b847c9f2 100644
--- a/tests/util/format.h
+++ b/tests/util/format.h
@@ -55,6 +55,7 @@ struct util_yuv_info {
 struct util_format_info {
 	uint32_t format;
 	const char *name;
+	unsigned int ncolors;
 	const struct util_rgb_info rgb;
 	const struct util_yuv_info yuv;
 };
diff --git a/tests/util/kms.c b/tests/util/kms.c
index 39a93866..8bbc2275 100644
--- a/tests/util/kms.c
+++ b/tests/util/kms.c
@@ -96,33 +96,6 @@ const char *util_lookup_connector_status_name(unsigned int status)
 				     ARRAY_SIZE(connector_status_names));
 }
 
-static const struct type_name connector_type_names[] = {
-	{ DRM_MODE_CONNECTOR_Unknown, "unknown" },
-	{ DRM_MODE_CONNECTOR_VGA, "VGA" },
-	{ DRM_MODE_CONNECTOR_DVII, "DVI-I" },
-	{ DRM_MODE_CONNECTOR_DVID, "DVI-D" },
-	{ DRM_MODE_CONNECTOR_DVIA, "DVI-A" },
-	{ DRM_MODE_CONNECTOR_Composite, "composite" },
-	{ DRM_MODE_CONNECTOR_SVIDEO, "s-video" },
-	{ DRM_MODE_CONNECTOR_LVDS, "LVDS" },
-	{ DRM_MODE_CONNECTOR_Component, "component" },
-	{ DRM_MODE_CONNECTOR_9PinDIN, "9-pin DIN" },
-	{ DRM_MODE_CONNECTOR_DisplayPort, "DP" },
-	{ DRM_MODE_CONNECTOR_HDMIA, "HDMI-A" },
-	{ DRM_MODE_CONNECTOR_HDMIB, "HDMI-B" },
-	{ DRM_MODE_CONNECTOR_TV, "TV" },
-	{ DRM_MODE_CONNECTOR_eDP, "eDP" },
-	{ DRM_MODE_CONNECTOR_VIRTUAL, "Virtual" },
-	{ DRM_MODE_CONNECTOR_DSI, "DSI" },
-	{ DRM_MODE_CONNECTOR_DPI, "DPI" },
-};
-
-const char *util_lookup_connector_type_name(unsigned int type)
-{
-	return util_lookup_type_name(type, connector_type_names,
-				     ARRAY_SIZE(connector_type_names));
-}
-
 static const char * const modules[] = {
 	"i915",
 	"amdgpu",
@@ -150,6 +123,10 @@ static const char * const modules[] = {
 	"komeda",
 	"imx-dcss",
 	"mxsfb-drm",
+	"simpledrm",
+	"imx-lcdif",
+	"vkms",
+	"tidss",
 };
 
 int util_open(const char *device, const char *module)
diff --git a/tests/util/kms.h b/tests/util/kms.h
index dde2ed2c..f79f4617 100644
--- a/tests/util/kms.h
+++ b/tests/util/kms.h
@@ -28,7 +28,6 @@
 
 const char *util_lookup_encoder_type_name(unsigned int type);
 const char *util_lookup_connector_status_name(unsigned int type);
-const char *util_lookup_connector_type_name(unsigned int type);
 
 int util_open(const char *device, const char *module);
 
diff --git a/tests/util/pattern.c b/tests/util/pattern.c
index 158c0b16..2ff9c033 100644
--- a/tests/util/pattern.c
+++ b/tests/util/pattern.c
@@ -23,6 +23,7 @@
  * IN THE SOFTWARE.
  */
 
+#include <stdbool.h>
 #include <stdint.h>
 #include <stdio.h>
 #include <stdlib.h>
@@ -61,6 +62,33 @@ struct color_yuv {
 	  .u = MAKE_YUV_601_U(r, g, b), \
 	  .v = MAKE_YUV_601_V(r, g, b) }
 
+static inline uint16_t swap16(uint16_t x)
+{
+	return ((x & 0x00ffU) << 8) | ((x & 0xff00U) >> 8);
+}
+
+static inline uint32_t swap32(uint32_t x)
+{
+	return ((x & 0x000000ffU) << 24) |
+	       ((x & 0x0000ff00U) <<  8) |
+	       ((x & 0x00ff0000U) >>  8) |
+	       ((x & 0xff000000U) >> 24);
+}
+
+#ifdef HAVE_BIG_ENDIAN
+#define cpu_to_be16(x)			(x)
+#define cpu_to_le16(x)			swap16(x)
+#define cpu_to_le32(x)			swap32(x)
+#define fb_foreign_endian(format)	(!((format) & DRM_FORMAT_BIG_ENDIAN))
+#else
+#define cpu_to_be16(x)			swap16(x)
+#define cpu_to_le16(x)			(x)
+#define cpu_to_le32(x)			(x)
+#define fb_foreign_endian(format)	((format) & DRM_FORMAT_BIG_ENDIAN)
+#endif
+
+#define cpu_to_fb16(x)	(fb_be ? cpu_to_be16(x) : cpu_to_le16(x))
+
 /* This function takes 8-bit color values */
 static inline uint32_t shiftcolor8(const struct util_color_component *comp,
 				  uint32_t value)
@@ -162,7 +190,7 @@ static void fill_smpte_yuv_planar(const struct util_yuv_info *yuv,
 				  unsigned int height, unsigned int stride)
 {
 	const struct color_yuv colors_top[] = {
-		MAKE_YUV_601(191, 192, 192),	/* grey */
+		MAKE_YUV_601(192, 192, 192),	/* grey */
 		MAKE_YUV_601(192, 192, 0),	/* yellow */
 		MAKE_YUV_601(0, 192, 192),	/* cyan */
 		MAKE_YUV_601(0, 192, 0),	/* green */
@@ -260,12 +288,154 @@ static void fill_smpte_yuv_planar(const struct util_yuv_info *yuv,
 	}
 }
 
+static void write_pixels_10bpp(unsigned char *mem,
+			       unsigned short a,
+			       unsigned short b,
+			       unsigned short c,
+			       unsigned short d)
+{
+	  mem[0] = (a & 0xff);
+	  mem[1] = ((a >> 8) & 0x3) | ((b & 0x3f) << 2);
+	  mem[2] = ((b >> 6) & 0xf) | ((c & 0xf) << 4);
+	  mem[3] = ((c >> 4) & 0x3f) | ((d & 0x3) << 6);
+	  mem[4] = ((d >> 2) & 0xff);
+}
+
+static void fill_smpte_yuv_planar_10bpp(const struct util_yuv_info *yuv,
+					unsigned char *y_mem,
+					unsigned char *uv_mem,
+					unsigned int width,
+					unsigned int height,
+					unsigned int stride)
+{
+	const struct color_yuv colors_top[] = {
+		MAKE_YUV_601(192, 192, 192),	/* grey */
+		MAKE_YUV_601(192, 192, 0),	/* yellow */
+		MAKE_YUV_601(0, 192, 192),	/* cyan */
+		MAKE_YUV_601(0, 192, 0),	/* green */
+		MAKE_YUV_601(192, 0, 192),	/* magenta */
+		MAKE_YUV_601(192, 0, 0),	/* red */
+		MAKE_YUV_601(0, 0, 192),	/* blue */
+	};
+	const struct color_yuv colors_middle[] = {
+		MAKE_YUV_601(0, 0, 192),	/* blue */
+		MAKE_YUV_601(19, 19, 19),	/* black */
+		MAKE_YUV_601(192, 0, 192),	/* magenta */
+		MAKE_YUV_601(19, 19, 19),	/* black */
+		MAKE_YUV_601(0, 192, 192),	/* cyan */
+		MAKE_YUV_601(19, 19, 19),	/* black */
+		MAKE_YUV_601(192, 192, 192),	/* grey */
+	};
+	const struct color_yuv colors_bottom[] = {
+		MAKE_YUV_601(0, 33, 76),	/* in-phase */
+		MAKE_YUV_601(255, 255, 255),	/* super white */
+		MAKE_YUV_601(50, 0, 106),	/* quadrature */
+		MAKE_YUV_601(19, 19, 19),	/* black */
+		MAKE_YUV_601(9, 9, 9),		/* 3.5% */
+		MAKE_YUV_601(19, 19, 19),	/* 7.5% */
+		MAKE_YUV_601(29, 29, 29),	/* 11.5% */
+		MAKE_YUV_601(19, 19, 19),	/* black */
+	};
+	unsigned int cs = yuv->chroma_stride;
+	unsigned int xsub = yuv->xsub;
+	unsigned int ysub = yuv->ysub;
+	unsigned int xstep = cs * xsub;
+	unsigned int x;
+	unsigned int y;
+
+	/* Luma */
+	for (y = 0; y < height * 6 / 9; ++y) {
+		for (x = 0; x < width; x += 4)
+			write_pixels_10bpp(&y_mem[(x * 5) / 4],
+				colors_top[(x+0) * 7 / width].y << 2,
+				colors_top[(x+1) * 7 / width].y << 2,
+				colors_top[(x+2) * 7 / width].y << 2,
+				colors_top[(x+3) * 7 / width].y << 2);
+		y_mem += stride;
+	}
+
+	for (; y < height * 7 / 9; ++y) {
+		for (x = 0; x < width; x += 4)
+			write_pixels_10bpp(&y_mem[(x * 5) / 4],
+				colors_middle[(x+0) * 7 / width].y << 2,
+				colors_middle[(x+1) * 7 / width].y << 2,
+				colors_middle[(x+2) * 7 / width].y << 2,
+				colors_middle[(x+3) * 7 / width].y << 2);
+		y_mem += stride;
+	}
+
+	for (; y < height; ++y) {
+		for (x = 0; x < width * 5 / 7; x += 4)
+			write_pixels_10bpp(&y_mem[(x * 5) / 4],
+				colors_bottom[(x+0) * 4 / (width * 5 / 7)].y << 2,
+				colors_bottom[(x+1) * 4 / (width * 5 / 7)].y << 2,
+				colors_bottom[(x+2) * 4 / (width * 5 / 7)].y << 2,
+				colors_bottom[(x+3) * 4 / (width * 5 / 7)].y << 2);
+		for (; x < width * 6 / 7; x += 4)
+			write_pixels_10bpp(&y_mem[(x * 5) / 4],
+				colors_bottom[((x+0) - width * 5 / 7) * 3 / (width / 7) + 4].y << 2,
+				colors_bottom[((x+1) - width * 5 / 7) * 3 / (width / 7) + 4].y << 2,
+				colors_bottom[((x+2) - width * 5 / 7) * 3 / (width / 7) + 4].y << 2,
+				colors_bottom[((x+3) - width * 5 / 7) * 3 / (width / 7) + 4].y << 2);
+		for (; x < width; x += 4)
+			write_pixels_10bpp(&y_mem[(x * 5) / 4],
+				colors_bottom[7].y << 2,
+				colors_bottom[7].y << 2,
+				colors_bottom[7].y << 2,
+				colors_bottom[7].y << 2);
+		y_mem += stride;
+	}
+
+	/* Chroma */
+	for (y = 0; y < height * 6 / 9; y += ysub) {
+		for (x = 0; x < width; x += xstep)
+			write_pixels_10bpp(&uv_mem[(x * 5) / xstep],
+				colors_top[(x+0) * 7 / width].u << 2,
+				colors_top[(x+0) * 7 / width].v << 2,
+				colors_top[(x+xsub) * 7 / width].u << 2,
+				colors_top[(x+xsub) * 7 / width].v << 2);
+		uv_mem += stride * cs / xsub;
+	}
+
+	for (; y < height * 7 / 9; y += ysub) {
+		for (x = 0; x < width; x += xstep)
+			write_pixels_10bpp(&uv_mem[(x * 5) / xstep],
+				colors_middle[(x+0) * 7 / width].u << 2,
+				colors_middle[(x+0) * 7 / width].v << 2,
+				colors_middle[(x+xsub) * 7 / width].u << 2,
+				colors_middle[(x+xsub) * 7 / width].v << 2);
+		uv_mem += stride * cs / xsub;
+	}
+
+	for (; y < height; y += ysub) {
+		for (x = 0; x < width * 5 / 7; x += xstep)
+			write_pixels_10bpp(&uv_mem[(x * 5) / xstep],
+				colors_bottom[(x+0) * 4 / (width * 5 / 7)].u << 2,
+				colors_bottom[(x+0) * 4 / (width * 5 / 7)].v << 2,
+				colors_bottom[(x+xsub) * 4 / (width * 5 / 7)].u << 2,
+				colors_bottom[(x+xsub) * 4 / (width * 5 / 7)].v << 2);
+		for (; x < width * 6 / 7; x += xstep)
+			write_pixels_10bpp(&uv_mem[(x * 5) / xstep],
+				colors_bottom[((x+0) - width * 5 / 7) * 3 / (width / 7) + 4].u << 2,
+				colors_bottom[((x+0) - width * 5 / 7) * 3 / (width / 7) + 4].v << 2,
+				colors_bottom[((x+xsub) - width * 5 / 7) * 3 / (width / 7) + 4].u << 2,
+				colors_bottom[((x+xsub) - width * 5 / 7) * 3 / (width / 7) + 4].v << 2);
+		for (; x < width; x += xstep)
+			write_pixels_10bpp(&uv_mem[(x * 5) / xstep],
+				colors_bottom[7].u << 2,
+				colors_bottom[7].v << 2,
+				colors_bottom[7].u << 2,
+				colors_bottom[7].v << 2);
+		uv_mem += stride * cs / xsub;
+	}
+}
+
 static void fill_smpte_yuv_packed(const struct util_yuv_info *yuv, void *mem,
 				  unsigned int width, unsigned int height,
 				  unsigned int stride)
 {
 	const struct color_yuv colors_top[] = {
-		MAKE_YUV_601(191, 192, 192),	/* grey */
+		MAKE_YUV_601(192, 192, 192),	/* grey */
 		MAKE_YUV_601(192, 192, 0),	/* yellow */
 		MAKE_YUV_601(0, 192, 192),	/* cyan */
 		MAKE_YUV_601(0, 192, 0),	/* green */
@@ -361,7 +531,7 @@ static void fill_smpte_yuv_packed(const struct util_yuv_info *yuv, void *mem,
 
 static void fill_smpte_rgb16(const struct util_rgb_info *rgb, void *mem,
 			     unsigned int width, unsigned int height,
-			     unsigned int stride)
+			     unsigned int stride, bool fb_be)
 {
 	const uint16_t colors_top[] = {
 		MAKE_RGBA(rgb, 192, 192, 192, 255),	/* grey */
@@ -396,26 +566,26 @@ static void fill_smpte_rgb16(const struct util_rgb_info *rgb, void *mem,
 
 	for (y = 0; y < height * 6 / 9; ++y) {
 		for (x = 0; x < width; ++x)
-			((uint16_t *)mem)[x] = colors_top[x * 7 / width];
+			((uint16_t *)mem)[x] = cpu_to_fb16(colors_top[x * 7 / width]);
 		mem += stride;
 	}
 
 	for (; y < height * 7 / 9; ++y) {
 		for (x = 0; x < width; ++x)
-			((uint16_t *)mem)[x] = colors_middle[x * 7 / width];
+			((uint16_t *)mem)[x] = cpu_to_fb16(colors_middle[x * 7 / width]);
 		mem += stride;
 	}
 
 	for (; y < height; ++y) {
 		for (x = 0; x < width * 5 / 7; ++x)
 			((uint16_t *)mem)[x] =
-				colors_bottom[x * 4 / (width * 5 / 7)];
+				cpu_to_fb16(colors_bottom[x * 4 / (width * 5 / 7)]);
 		for (; x < width * 6 / 7; ++x)
 			((uint16_t *)mem)[x] =
-				colors_bottom[(x - width * 5 / 7) * 3
-					      / (width / 7) + 4];
+				cpu_to_fb16(colors_bottom[(x - width * 5 / 7) * 3
+							  / (width / 7) + 4]);
 		for (; x < width; ++x)
-			((uint16_t *)mem)[x] = colors_bottom[7];
+			((uint16_t *)mem)[x] = cpu_to_fb16(colors_bottom[7]);
 		mem += stride;
 	}
 }
@@ -520,26 +690,26 @@ static void fill_smpte_rgb32(const struct util_rgb_info *rgb, void *mem,
 
 	for (y = 0; y < height * 6 / 9; ++y) {
 		for (x = 0; x < width; ++x)
-			((uint32_t *)mem)[x] = colors_top[x * 7 / width];
+			((uint32_t *)mem)[x] = cpu_to_le32(colors_top[x * 7 / width]);
 		mem += stride;
 	}
 
 	for (; y < height * 7 / 9; ++y) {
 		for (x = 0; x < width; ++x)
-			((uint32_t *)mem)[x] = colors_middle[x * 7 / width];
+			((uint32_t *)mem)[x] = cpu_to_le32(colors_middle[x * 7 / width]);
 		mem += stride;
 	}
 
 	for (; y < height; ++y) {
 		for (x = 0; x < width * 5 / 7; ++x)
 			((uint32_t *)mem)[x] =
-				colors_bottom[x * 4 / (width * 5 / 7)];
+				cpu_to_le32(colors_bottom[x * 4 / (width * 5 / 7)]);
 		for (; x < width * 6 / 7; ++x)
 			((uint32_t *)mem)[x] =
-				colors_bottom[(x - width * 5 / 7) * 3
-					      / (width / 7) + 4];
+				cpu_to_le32(colors_bottom[(x - width * 5 / 7) * 3
+							  / (width / 7) + 4]);
 		for (; x < width; ++x)
-			((uint32_t *)mem)[x] = colors_bottom[7];
+			((uint32_t *)mem)[x] = cpu_to_le32(colors_bottom[7]);
 		mem += stride;
 	}
 }
@@ -605,6 +775,370 @@ static void fill_smpte_rgb16fp(const struct util_rgb_info *rgb, void *mem,
 	}
 }
 
+enum smpte_colors {
+	SMPTE_COLOR_GREY,
+	SMPTE_COLOR_YELLOW,
+	SMPTE_COLOR_CYAN,
+	SMPTE_COLOR_GREEN,
+	SMPTE_COLOR_MAGENTA,
+	SMPTE_COLOR_RED,
+	SMPTE_COLOR_BLUE,
+	SMPTE_COLOR_BLACK,
+	SMPTE_COLOR_IN_PHASE,
+	SMPTE_COLOR_SUPER_WHITE,
+	SMPTE_COLOR_QUADRATURE,
+	SMPTE_COLOR_3PC5,
+	SMPTE_COLOR_11PC5,
+};
+
+static unsigned int smpte_top[7] = {
+	SMPTE_COLOR_GREY,
+	SMPTE_COLOR_YELLOW,
+	SMPTE_COLOR_CYAN,
+	SMPTE_COLOR_GREEN,
+	SMPTE_COLOR_MAGENTA,
+	SMPTE_COLOR_RED,
+	SMPTE_COLOR_BLUE,
+};
+
+static unsigned int smpte_middle[7] = {
+	SMPTE_COLOR_BLUE,
+	SMPTE_COLOR_BLACK,
+	SMPTE_COLOR_MAGENTA,
+	SMPTE_COLOR_BLACK,
+	SMPTE_COLOR_CYAN,
+	SMPTE_COLOR_BLACK,
+	SMPTE_COLOR_GREY,
+};
+
+static unsigned int smpte_bottom[8] = {
+	SMPTE_COLOR_IN_PHASE,
+	SMPTE_COLOR_SUPER_WHITE,
+	SMPTE_COLOR_QUADRATURE,
+	SMPTE_COLOR_BLACK,
+	SMPTE_COLOR_3PC5,
+	SMPTE_COLOR_BLACK,
+	SMPTE_COLOR_11PC5,
+	SMPTE_COLOR_BLACK,
+};
+
+#define EXPAND_COLOR(r, g, b)	{ (r) * 0x101, (g) * 0x101, (b) * 0x101 }
+
+static const struct drm_color_lut bw_color_lut[] = {
+	EXPAND_COLOR(  0,   0,   0),	/* black */
+	EXPAND_COLOR(255, 255, 255),	/* white */
+};
+
+static const struct drm_color_lut pentile_color_lut[] = {
+	/* PenTile RG-GB */
+	EXPAND_COLOR(  0,   0,   0),	/* black */
+	EXPAND_COLOR(255,   0,   0),	/* red */
+	EXPAND_COLOR(  0, 207,   0),	/* green */
+	EXPAND_COLOR(  0,   0, 255),	/* blue */
+};
+
+static const struct drm_color_lut smpte_color_lut[] = {
+	[SMPTE_COLOR_GREY] =        EXPAND_COLOR(192, 192, 192),
+	[SMPTE_COLOR_YELLOW] =      EXPAND_COLOR(192, 192,   0),
+	[SMPTE_COLOR_CYAN] =        EXPAND_COLOR(  0, 192, 192),
+	[SMPTE_COLOR_GREEN] =       EXPAND_COLOR(  0, 192,   0),
+	[SMPTE_COLOR_MAGENTA] =     EXPAND_COLOR(192,   0, 192),
+	[SMPTE_COLOR_RED] =         EXPAND_COLOR(192,   0,   0),
+	[SMPTE_COLOR_BLUE] =        EXPAND_COLOR(  0,   0, 192),
+	[SMPTE_COLOR_BLACK] =       EXPAND_COLOR( 19,  19,  19),
+	[SMPTE_COLOR_IN_PHASE] =    EXPAND_COLOR(  0,  33,  76),
+	[SMPTE_COLOR_SUPER_WHITE] = EXPAND_COLOR(255, 255, 255),
+	[SMPTE_COLOR_QUADRATURE] =  EXPAND_COLOR( 50,   0, 106),
+	[SMPTE_COLOR_3PC5] =        EXPAND_COLOR(  9,   9,   9),
+	[SMPTE_COLOR_11PC5] =       EXPAND_COLOR( 29,  29,  29),
+};
+
+#undef EXPAND_COLOR
+
+/*
+ * Floyd-Steinberg dithering
+ */
+
+struct fsd {
+	unsigned int width;
+	unsigned int x;
+	unsigned int i;
+	int red;
+	int green;
+	int blue;
+	int error[];
+};
+
+static struct fsd *fsd_alloc(unsigned int width)
+{
+	unsigned int n = 3 * (width + 1);
+	struct fsd *fsd = malloc(sizeof(*fsd) + n * sizeof(fsd->error[0]));
+
+	fsd->width = width;
+	fsd->x = 0;
+	fsd->i = 0;
+	memset(fsd->error, 0, n * sizeof(fsd->error[0]));
+
+	return fsd;
+}
+
+static inline int clamp(int val, int min, int max)
+{
+	if (val < min)
+		return min;
+	if (val > max)
+		return max;
+	return val;
+}
+
+static void fsd_dither(struct fsd *fsd, struct drm_color_lut *color)
+{
+	unsigned int i = fsd->i;
+
+	fsd->red = (int)color->red + (fsd->error[3 * i] + 8) / 16;
+	fsd->green = (int)color->green + (fsd->error[3 * i + 1] + 8) / 16;
+	fsd->blue = (int)color->blue + (fsd->error[3 * i + 2] + 8) / 16;
+
+	color->red = clamp(fsd->red, 0, 65535);
+	color->green = clamp(fsd->green, 0, 65535);
+	color->blue = clamp(fsd->blue, 0, 65535);
+}
+
+static void fsd_update(struct fsd *fsd, const struct drm_color_lut *actual)
+{
+	int error_red = fsd->red - (int)actual->red;
+	int error_green = fsd->green - (int)actual->green;
+	int error_blue = fsd->blue - (int)actual->blue;
+	unsigned int width = fsd->width;
+	unsigned int i = fsd->i, j;
+	unsigned int n = width + 1;
+
+	/* Distribute errors over neighboring pixels */
+	if (fsd->x == width - 1) {
+		/* Last pixel on this scanline */
+		/* South East: initialize to zero */
+		fsd->error[3 * i] = 0;
+		fsd->error[3 * i + 1] = 0;
+		fsd->error[3 * i + 2] = 0;
+	} else {
+		/* East: accumulate error */
+		j = (i + 1) % n;
+		fsd->error[3 * j] += 7 * error_red;
+		fsd->error[3 * j + 1] += 7 * error_green;
+		fsd->error[3 * j + 2] += 7 * error_blue;
+
+		/* South East: initial error */
+		fsd->error[3 * i] = error_red;
+		fsd->error[3 * i + 1] = error_green;
+		fsd->error[3 * i + 2] = error_blue;
+	}
+	/* South West: accumulate error */
+	j = (i + width - 1) % n;
+	fsd->error[3 * j] += 3 * error_red;
+	fsd->error[3 * j + 1] += 3 * error_green;
+	fsd->error[3 * j + 2] += 3 * error_blue;
+
+	/* South: accumulate error */
+	j = (i + width) % n;
+	fsd->error[3 * j] += 5 * error_red;
+	fsd->error[3 * j + 1] += 5 * error_green;
+	fsd->error[3 * j + 2] += 5 * error_blue;
+
+	fsd->x = (fsd->x + 1) % width;
+	fsd->i = (fsd->i + 1) % n;
+}
+
+static void write_pixel_1(uint8_t *mem, unsigned int x, unsigned int pixel)
+{
+	unsigned int shift = 7 - (x & 7);
+	unsigned int mask = 1U << shift;
+
+	mem[x / 8] = (mem[x / 8] & ~mask) | ((pixel << shift) & mask);
+}
+
+static void write_color_1(struct fsd *fsd, uint8_t *mem, unsigned int x,
+			  unsigned int index)
+{
+	struct drm_color_lut color = smpte_color_lut[index];
+	unsigned int pixel;
+
+	fsd_dither(fsd, &color);
+
+	/* ITU BT.601: Y = 0.299 R + 0.587 G + 0.114 B */
+	if (3 * color.red + 6 * color.green + color.blue >= 10 * 32768) {
+		pixel = 1;
+		color.red = color.green = color.blue = 65535;
+	} else {
+		pixel = 0;
+		color.red = color.green = color.blue = 0;
+	}
+
+	fsd_update(fsd, &color);
+
+	write_pixel_1(mem, x, pixel);
+}
+
+static void fill_smpte_c1(void *mem, unsigned int width, unsigned int height,
+			  unsigned int stride)
+{
+	struct fsd *fsd = fsd_alloc(width);
+	unsigned int x;
+	unsigned int y;
+
+	for (y = 0; y < height * 6 / 9; ++y) {
+		for (x = 0; x < width; ++x)
+			write_color_1(fsd, mem, x, smpte_top[x * 7 / width]);
+		mem += stride;
+	}
+
+	for (; y < height * 7 / 9; ++y) {
+		for (x = 0; x < width; ++x)
+			write_color_1(fsd, mem, x, smpte_middle[x * 7 / width]);
+		mem += stride;
+	}
+
+	for (; y < height; ++y) {
+		for (x = 0; x < width * 5 / 7; ++x)
+			write_color_1(fsd, mem, x,
+				      smpte_bottom[x * 4 / (width * 5 / 7)]);
+		for (; x < width * 6 / 7; ++x)
+			write_color_1(fsd, mem, x,
+				      smpte_bottom[(x - width * 5 / 7) * 3 /
+						   (width / 7) + 4]);
+		for (; x < width; ++x)
+			write_color_1(fsd, mem, x, smpte_bottom[7]);
+		mem += stride;
+	}
+
+	free(fsd);
+}
+
+static void write_pixel_2(uint8_t *mem, unsigned int x, unsigned int pixel)
+{
+	unsigned int shift = 6 - 2 * (x & 3);
+	unsigned int mask = 3U << shift;
+
+	mem[x / 4] = (mem[x / 4] & ~mask) | ((pixel << shift) & mask);
+}
+
+static void write_color_2(struct fsd *fsd, uint8_t *mem, unsigned int stride,
+			  unsigned int x, unsigned int index)
+{
+	struct drm_color_lut color = smpte_color_lut[index];
+	unsigned int r, g, b;
+
+	fsd_dither(fsd, &color);
+
+	if (color.red >= 32768) {
+		r = 1;
+		color.red = 65535;
+	} else {
+		r = 0;
+		color.red = 0;
+	}
+	if (color.green >= 32768) {
+		g = 2;
+		color.green = 65535;
+	} else {
+		g = 0;
+		color.green = 0;
+	}
+	if (color.blue >= 32768) {
+		b = 3;
+		color.blue = 65535;
+	} else {
+		b = 0;
+		color.blue = 0;
+	}
+
+	fsd_update(fsd, &color);
+
+	/* Use PenTile RG-GB */
+	write_pixel_2(mem, 2 * x, r);
+	write_pixel_2(mem, 2 * x + 1, g);
+	write_pixel_2(mem + stride, 2 * x, g);
+	write_pixel_2(mem + stride, 2 * x + 1, b);
+}
+
+static void fill_smpte_c2(void *mem, unsigned int width, unsigned int height,
+			  unsigned int stride)
+{
+	struct fsd *fsd = fsd_alloc(width);
+	unsigned int x;
+	unsigned int y;
+
+	/* Half resolution for PenTile RG-GB */
+	width /= 2;
+	height /= 2;
+
+	for (y = 0; y < height * 6 / 9; ++y) {
+		for (x = 0; x < width; ++x)
+			write_color_2(fsd, mem, stride, x, smpte_top[x * 7 / width]);
+		mem += 2 * stride;
+	}
+
+	for (; y < height * 7 / 9; ++y) {
+		for (x = 0; x < width; ++x)
+			write_color_2(fsd, mem, stride, x, smpte_middle[x * 7 / width]);
+		mem += 2 * stride;
+	}
+
+	for (; y < height; ++y) {
+		for (x = 0; x < width * 5 / 7; ++x)
+			write_color_2(fsd, mem, stride, x,
+				      smpte_bottom[x * 4 / (width * 5 / 7)]);
+		for (; x < width * 6 / 7; ++x)
+			write_color_2(fsd, mem, stride, x,
+				      smpte_bottom[(x - width * 5 / 7) * 3 /
+						   (width / 7) + 4]);
+		for (; x < width; ++x)
+			write_color_2(fsd, mem, stride, x, smpte_bottom[7]);
+		mem += 2 * stride;
+	}
+
+	free(fsd);
+}
+
+static void write_pixel_4(uint8_t *mem, unsigned int x, unsigned int pixel)
+{
+	if (x & 1)
+		mem[x / 2] = (mem[x / 2] & 0xf0) | (pixel & 0x0f);
+	else
+		mem[x / 2] = (mem[x / 2] & 0x0f) | (pixel << 4);
+}
+
+static void fill_smpte_c4(void *mem, unsigned int width, unsigned int height,
+			  unsigned int stride)
+{
+	unsigned int x;
+	unsigned int y;
+
+	for (y = 0; y < height * 6 / 9; ++y) {
+		for (x = 0; x < width; ++x)
+			write_pixel_4(mem, x, smpte_top[x * 7 / width]);
+		mem += stride;
+	}
+
+	for (; y < height * 7 / 9; ++y) {
+		for (x = 0; x < width; ++x)
+			write_pixel_4(mem, x, smpte_middle[x * 7 / width]);
+		mem += stride;
+	}
+
+	for (; y < height; ++y) {
+		for (x = 0; x < width * 5 / 7; ++x)
+			write_pixel_4(mem, x,
+				      smpte_bottom[x * 4 / (width * 5 / 7)]);
+		for (; x < width * 6 / 7; ++x)
+			write_pixel_4(mem, x,
+				      smpte_bottom[(x - width * 5 / 7) * 3 /
+						   (width / 7) + 4]);
+		for (; x < width; ++x)
+			write_pixel_4(mem, x, smpte_bottom[7]);
+		mem += stride;
+	}
+}
+
 static void fill_smpte_c8(void *mem, unsigned int width, unsigned int height,
 			  unsigned int stride)
 {
@@ -613,69 +1147,45 @@ static void fill_smpte_c8(void *mem, unsigned int width, unsigned int height,
 
 	for (y = 0; y < height * 6 / 9; ++y) {
 		for (x = 0; x < width; ++x)
-			((uint8_t *)mem)[x] = x * 7 / width;
+			((uint8_t *)mem)[x] = smpte_top[x * 7 / width];
 		mem += stride;
 	}
 
 	for (; y < height * 7 / 9; ++y) {
 		for (x = 0; x < width; ++x)
-			((uint8_t *)mem)[x] = 7 + (x * 7 / width);
+			((uint8_t *)mem)[x] = smpte_middle[x * 7 / width];
 		mem += stride;
 	}
 
 	for (; y < height; ++y) {
 		for (x = 0; x < width * 5 / 7; ++x)
 			((uint8_t *)mem)[x] =
-				14 + (x * 4 / (width * 5 / 7));
+				smpte_bottom[x * 4 / (width * 5 / 7)];
 		for (; x < width * 6 / 7; ++x)
 			((uint8_t *)mem)[x] =
-				14 + ((x - width * 5 / 7) * 3
-					      / (width / 7) + 4);
+				smpte_bottom[(x - width * 5 / 7) * 3
+					     / (width / 7) + 4];
 		for (; x < width; ++x)
-			((uint8_t *)mem)[x] = 14 + 7;
+			((uint8_t *)mem)[x] = smpte_bottom[7];
 		mem += stride;
 	}
 }
 
-void util_smpte_c8_gamma(unsigned size, struct drm_color_lut *lut)
+void util_smpte_fill_lut(unsigned int ncolors, struct drm_color_lut *lut)
 {
-	if (size < 7 + 7 + 8) {
-		printf("Error: gamma too small: %d < %d\n", size, 7 + 7 + 8);
+	if (ncolors < ARRAY_SIZE(bw_color_lut)) {
+		printf("Error: lut too small: %u < %zu\n", ncolors,
+		       ARRAY_SIZE(bw_color_lut));
 		return;
 	}
-	memset(lut, 0, size * sizeof(struct drm_color_lut));
-
-#define FILL_COLOR(idx, r, g, b) \
-	lut[idx].red = (r) << 8; \
-	lut[idx].green = (g) << 8; \
-	lut[idx].blue = (b) << 8
-
-	FILL_COLOR( 0, 192, 192, 192);	/* grey */
-	FILL_COLOR( 1, 192, 192, 0  );	/* yellow */
-	FILL_COLOR( 2, 0,   192, 192);	/* cyan */
-	FILL_COLOR( 3, 0,   192, 0  );	/* green */
-	FILL_COLOR( 4, 192, 0,   192);	/* magenta */
-	FILL_COLOR( 5, 192, 0,   0  );	/* red */
-	FILL_COLOR( 6, 0,   0,   192);	/* blue */
-
-	FILL_COLOR( 7, 0,   0,   192);	/* blue */
-	FILL_COLOR( 8, 19,  19,  19 );	/* black */
-	FILL_COLOR( 9, 192, 0,   192);	/* magenta */
-	FILL_COLOR(10, 19,  19,  19 );	/* black */
-	FILL_COLOR(11, 0,   192, 192);	/* cyan */
-	FILL_COLOR(12, 19,  19,  19 );	/* black */
-	FILL_COLOR(13, 192, 192, 192);	/* grey */
-
-	FILL_COLOR(14, 0,   33,  76);	/* in-phase */
-	FILL_COLOR(15, 255, 255, 255);	/* super white */
-	FILL_COLOR(16, 50,  0,   106);	/* quadrature */
-	FILL_COLOR(17, 19,  19,  19);	/* black */
-	FILL_COLOR(18, 9,   9,   9);	/* 3.5% */
-	FILL_COLOR(19, 19,  19,  19);	/* 7.5% */
-	FILL_COLOR(20, 29,  29,  29);	/* 11.5% */
-	FILL_COLOR(21, 19,  19,  19);	/* black */
-
-#undef FILL_COLOR
+	memset(lut, 0, ncolors * sizeof(struct drm_color_lut));
+
+	if (ncolors < ARRAY_SIZE(pentile_color_lut))
+		memcpy(lut, bw_color_lut, sizeof(bw_color_lut));
+	else if (ncolors < ARRAY_SIZE(smpte_color_lut))
+		memcpy(lut, pentile_color_lut, sizeof(pentile_color_lut));
+	else
+		memcpy(lut, smpte_color_lut, sizeof(smpte_color_lut));
 }
 
 static void fill_smpte(const struct util_format_info *info, void *planes[3],
@@ -685,6 +1195,12 @@ static void fill_smpte(const struct util_format_info *info, void *planes[3],
 	unsigned char *u, *v;
 
 	switch (info->format) {
+	case DRM_FORMAT_C1:
+		return fill_smpte_c1(planes[0], width, height, stride);
+	case DRM_FORMAT_C2:
+		return fill_smpte_c2(planes[0], width, height, stride);
+	case DRM_FORMAT_C4:
+		return fill_smpte_c4(planes[0], width, height, stride);
 	case DRM_FORMAT_C8:
 		return fill_smpte_c8(planes[0], width, height, stride);
 	case DRM_FORMAT_UYVY:
@@ -698,11 +1214,20 @@ static void fill_smpte(const struct util_format_info *info, void *planes[3],
 	case DRM_FORMAT_NV21:
 	case DRM_FORMAT_NV16:
 	case DRM_FORMAT_NV61:
+	case DRM_FORMAT_NV24:
+	case DRM_FORMAT_NV42:
 		u = info->yuv.order & YUV_YCbCr ? planes[1] : planes[1] + 1;
 		v = info->yuv.order & YUV_YCrCb ? planes[1] : planes[1] + 1;
 		return fill_smpte_yuv_planar(&info->yuv, planes[0], u, v,
 					     width, height, stride);
 
+	case DRM_FORMAT_NV15:
+	case DRM_FORMAT_NV20:
+	case DRM_FORMAT_NV30:
+		return fill_smpte_yuv_planar_10bpp(&info->yuv, planes[0],
+						   planes[1], width, height,
+						   stride);
+
 	case DRM_FORMAT_YUV420:
 		return fill_smpte_yuv_planar(&info->yuv, planes[0], planes[1],
 					     planes[2], width, height, stride);
@@ -720,9 +1245,11 @@ static void fill_smpte(const struct util_format_info *info, void *planes[3],
 	case DRM_FORMAT_BGRA4444:
 	case DRM_FORMAT_BGRX4444:
 	case DRM_FORMAT_RGB565:
+	case DRM_FORMAT_RGB565 | DRM_FORMAT_BIG_ENDIAN:
 	case DRM_FORMAT_BGR565:
 	case DRM_FORMAT_ARGB1555:
 	case DRM_FORMAT_XRGB1555:
+	case DRM_FORMAT_XRGB1555 | DRM_FORMAT_BIG_ENDIAN:
 	case DRM_FORMAT_ABGR1555:
 	case DRM_FORMAT_XBGR1555:
 	case DRM_FORMAT_RGBA5551:
@@ -730,7 +1257,8 @@ static void fill_smpte(const struct util_format_info *info, void *planes[3],
 	case DRM_FORMAT_BGRA5551:
 	case DRM_FORMAT_BGRX5551:
 		return fill_smpte_rgb16(&info->rgb, planes[0],
-					width, height, stride);
+					width, height, stride,
+					info->format & DRM_FORMAT_BIG_ENDIAN);
 
 	case DRM_FORMAT_BGR888:
 	case DRM_FORMAT_RGB888:
@@ -764,10 +1292,31 @@ static void fill_smpte(const struct util_format_info *info, void *planes[3],
 	}
 }
 
-/* swap these for big endian.. */
-#define RED   2
-#define GREEN 1
-#define BLUE  0
+#if HAVE_CAIRO
+static void byteswap_buffer16(void *mem, unsigned int width, unsigned int height,
+			      unsigned int stride)
+{
+	unsigned int x, y;
+
+	for (y = 0; y < height; ++y) {
+		for (x = 0; x < width; ++x)
+			((uint16_t *)mem)[x] = swap16(((uint16_t *)mem)[x]);
+		mem += stride;
+	}
+}
+
+static void byteswap_buffer32(void *mem, unsigned int width, unsigned int height,
+			      unsigned int stride)
+{
+	unsigned int x, y;
+
+	for (y = 0; y < height; ++y) {
+		for (x = 0; x < width; ++x)
+			((uint32_t *)mem)[x] = swap32(((uint32_t *)mem)[x]);
+		mem += stride;
+	}
+}
+#endif
 
 static void make_pwetty(void *data, unsigned int width, unsigned int height,
 			unsigned int stride, uint32_t format)
@@ -776,6 +1325,8 @@ static void make_pwetty(void *data, unsigned int width, unsigned int height,
 	cairo_surface_t *surface;
 	cairo_t *cr;
 	cairo_format_t cairo_format;
+	bool swap16 = false;
+	bool swap32 = false;
 
 	/* we can ignore the order of R,G,B channels */
 	switch (format) {
@@ -786,8 +1337,10 @@ static void make_pwetty(void *data, unsigned int width, unsigned int height,
 		cairo_format = CAIRO_FORMAT_ARGB32;
 		break;
 	case DRM_FORMAT_RGB565:
+	case DRM_FORMAT_RGB565 | DRM_FORMAT_BIG_ENDIAN:
 	case DRM_FORMAT_BGR565:
 		cairo_format = CAIRO_FORMAT_RGB16_565;
+		swap16 = fb_foreign_endian(format);
 		break;
 #if CAIRO_VERSION_MAJOR > 1 || (CAIRO_VERSION_MAJOR == 1 && CAIRO_VERSION_MINOR >= 12)
 	case DRM_FORMAT_ARGB2101010:
@@ -795,12 +1348,19 @@ static void make_pwetty(void *data, unsigned int width, unsigned int height,
 	case DRM_FORMAT_ABGR2101010:
 	case DRM_FORMAT_XBGR2101010:
 		cairo_format = CAIRO_FORMAT_RGB30;
+		swap32 = fb_foreign_endian(format);
 		break;
 #endif
 	default:
 		return;
 	}
 
+	/* Cairo uses native byte order, so we may have to byteswap before... */
+	if (swap16)
+		byteswap_buffer16(data, width, height, stride);
+	if (swap32)
+		byteswap_buffer32(data, width, height, stride);
+
 	surface = cairo_image_surface_create_for_data(data,
 						      cairo_format,
 						      width, height,
@@ -836,9 +1396,27 @@ static void make_pwetty(void *data, unsigned int width, unsigned int height,
 		}
 
 	cairo_destroy(cr);
+
+	/* ... and after */
+	if (swap16)
+		byteswap_buffer16(data, width, height, stride);
+	if (swap32)
+		byteswap_buffer32(data, width, height, stride);
 #endif
 }
 
+static struct color_yuv make_tiles_yuv_color(unsigned int x, unsigned int y,
+					     unsigned int width)
+{
+	div_t d = div(x+y, width);
+	uint32_t rgb32 = 0x00130502 * (d.quot >> 6)
+		       + 0x000a1120 * (d.rem >> 6);
+	struct color_yuv color =
+		MAKE_YUV_601((rgb32 >> 16) & 0xff, (rgb32 >> 8) & 0xff,
+			     rgb32 & 0xff);
+	return color;
+}
+
 static void fill_tiles_yuv_planar(const struct util_format_info *info,
 				  unsigned char *y_mem, unsigned char *u_mem,
 				  unsigned char *v_mem, unsigned int width,
@@ -853,12 +1431,8 @@ static void fill_tiles_yuv_planar(const struct util_format_info *info,
 
 	for (y = 0; y < height; ++y) {
 		for (x = 0; x < width; ++x) {
-			div_t d = div(x+y, width);
-			uint32_t rgb32 = 0x00130502 * (d.quot >> 6)
-				       + 0x000a1120 * (d.rem >> 6);
 			struct color_yuv color =
-				MAKE_YUV_601((rgb32 >> 16) & 0xff,
-					     (rgb32 >> 8) & 0xff, rgb32 & 0xff);
+				make_tiles_yuv_color(x, y, width);
 
 			y_mem[x] = color.y;
 			u_mem[x/xsub*cs] = color.u;
@@ -873,6 +1447,45 @@ static void fill_tiles_yuv_planar(const struct util_format_info *info,
 	}
 }
 
+static void fill_tiles_yuv_planar_10bpp(const struct util_format_info *info,
+					unsigned char *y_mem,
+					unsigned char *uv_mem,
+					unsigned int width,
+					unsigned int height,
+					unsigned int stride)
+{
+	const struct util_yuv_info *yuv = &info->yuv;
+	unsigned int cs = yuv->chroma_stride;
+	unsigned int xsub = yuv->xsub;
+	unsigned int ysub = yuv->ysub;
+	unsigned int xstep = cs * xsub;
+	unsigned int x;
+	unsigned int y;
+
+	for (y = 0; y < height; ++y) {
+		for (x = 0; x < width; x += 4) {
+			struct color_yuv a = make_tiles_yuv_color(x+0, y, width);
+			struct color_yuv b = make_tiles_yuv_color(x+1, y, width);
+			struct color_yuv c = make_tiles_yuv_color(x+2, y, width);
+			struct color_yuv d = make_tiles_yuv_color(x+3, y, width);
+
+			write_pixels_10bpp(&y_mem[(x * 5) / 4],
+				a.y << 2, b.y << 2, c.y << 2, d.y << 2);
+		}
+		y_mem += stride;
+	}
+	for (y = 0; y < height; y += ysub) {
+		for (x = 0; x < width; x += xstep) {
+			struct color_yuv a = make_tiles_yuv_color(x+0, y, width);
+			struct color_yuv b = make_tiles_yuv_color(x+xsub, y, width);
+
+			write_pixels_10bpp(&uv_mem[(x * 5) / xstep],
+				a.u << 2, a.v << 2, b.u << 2, b.v << 2);
+		}
+		uv_mem += stride * cs / xsub;
+	}
+}
+
 static void fill_tiles_yuv_packed(const struct util_format_info *info,
 				  void *mem, unsigned int width,
 				  unsigned int height, unsigned int stride)
@@ -887,12 +1500,8 @@ static void fill_tiles_yuv_packed(const struct util_format_info *info,
 
 	for (y = 0; y < height; ++y) {
 		for (x = 0; x < width; x += 2) {
-			div_t d = div(x+y, width);
-			uint32_t rgb32 = 0x00130502 * (d.quot >> 6)
-				       + 0x000a1120 * (d.rem >> 6);
 			struct color_yuv color =
-				MAKE_YUV_601((rgb32 >> 16) & 0xff,
-					     (rgb32 >> 8) & 0xff, rgb32 & 0xff);
+				make_tiles_yuv_color(x, y, width);
 
 			y_mem[2*x] = color.y;
 			c_mem[2*x+u] = color.u;
@@ -907,7 +1516,7 @@ static void fill_tiles_yuv_packed(const struct util_format_info *info,
 
 static void fill_tiles_rgb16(const struct util_format_info *info, void *mem,
 			     unsigned int width, unsigned int height,
-			     unsigned int stride)
+			     unsigned int stride, bool fb_be)
 {
 	const struct util_rgb_info *rgb = &info->rgb;
 	void *mem_base = mem;
@@ -923,7 +1532,7 @@ static void fill_tiles_rgb16(const struct util_format_info *info, void *mem,
 					  (rgb32 >> 8) & 0xff, rgb32 & 0xff,
 					  255);
 
-			((uint16_t *)mem)[x] = color;
+			((uint16_t *)mem)[x] = cpu_to_fb16(color);
 		}
 		mem += stride;
 	}
@@ -972,7 +1581,7 @@ static void fill_tiles_rgb32(const struct util_format_info *info, void *mem,
 					  (rgb32 >> 8) & 0xff, rgb32 & 0xff,
 					  alpha);
 
-			((uint32_t *)mem)[x] = color;
+			((uint32_t *)mem)[x] = cpu_to_le32(color);
 		}
 		mem += stride;
 	}
@@ -1023,11 +1632,19 @@ static void fill_tiles(const struct util_format_info *info, void *planes[3],
 	case DRM_FORMAT_NV21:
 	case DRM_FORMAT_NV16:
 	case DRM_FORMAT_NV61:
+	case DRM_FORMAT_NV24:
+	case DRM_FORMAT_NV42:
 		u = info->yuv.order & YUV_YCbCr ? planes[1] : planes[1] + 1;
 		v = info->yuv.order & YUV_YCrCb ? planes[1] : planes[1] + 1;
 		return fill_tiles_yuv_planar(info, planes[0], u, v,
 					     width, height, stride);
 
+	case DRM_FORMAT_NV15:
+	case DRM_FORMAT_NV20:
+	case DRM_FORMAT_NV30:
+		return fill_tiles_yuv_planar_10bpp(info, planes[0], planes[1],
+						   width, height, stride);
+
 	case DRM_FORMAT_YUV420:
 		return fill_tiles_yuv_planar(info, planes[0], planes[1],
 					     planes[2], width, height, stride);
@@ -1045,9 +1662,11 @@ static void fill_tiles(const struct util_format_info *info, void *planes[3],
 	case DRM_FORMAT_BGRA4444:
 	case DRM_FORMAT_BGRX4444:
 	case DRM_FORMAT_RGB565:
+	case DRM_FORMAT_RGB565 | DRM_FORMAT_BIG_ENDIAN:
 	case DRM_FORMAT_BGR565:
 	case DRM_FORMAT_ARGB1555:
 	case DRM_FORMAT_XRGB1555:
+	case DRM_FORMAT_XRGB1555 | DRM_FORMAT_BIG_ENDIAN:
 	case DRM_FORMAT_ABGR1555:
 	case DRM_FORMAT_XBGR1555:
 	case DRM_FORMAT_RGBA5551:
@@ -1055,7 +1674,8 @@ static void fill_tiles(const struct util_format_info *info, void *planes[3],
 	case DRM_FORMAT_BGRA5551:
 	case DRM_FORMAT_BGRX5551:
 		return fill_tiles_rgb16(info, planes[0],
-					width, height, stride);
+					width, height, stride,
+					info->format & DRM_FORMAT_BIG_ENDIAN);
 
 	case DRM_FORMAT_BGR888:
 	case DRM_FORMAT_RGB888:
@@ -1119,7 +1739,7 @@ static void fill_gradient_rgb32(const struct util_rgb_info *rgb,
 
 		for (j = 0; j < width / 2; j++) {
 			uint32_t value = MAKE_RGBA10(rgb, j & 0x3ff, j & 0x3ff, j & 0x3ff, 0);
-			row[2*j] = row[2*j+1] = value;
+			row[2*j] = row[2*j+1] = cpu_to_le32(value);
 		}
 		mem += stride;
 	}
@@ -1129,7 +1749,7 @@ static void fill_gradient_rgb32(const struct util_rgb_info *rgb,
 
 		for (j = 0; j < width / 2; j++) {
 			uint32_t value = MAKE_RGBA10(rgb, j & 0x3fc, j & 0x3fc, j & 0x3fc, 0);
-			row[2*j] = row[2*j+1] = value;
+			row[2*j] = row[2*j+1] = cpu_to_le32(value);
 		}
 		mem += stride;
 	}
diff --git a/tests/util/pattern.h b/tests/util/pattern.h
index ea38cafd..e500aba3 100644
--- a/tests/util/pattern.h
+++ b/tests/util/pattern.h
@@ -39,7 +39,7 @@ void util_fill_pattern(uint32_t format, enum util_fill_pattern pattern,
 		       void *planes[3], unsigned int width,
 		       unsigned int height, unsigned int stride);
 
-void util_smpte_c8_gamma(unsigned size, struct drm_color_lut *lut);
+void util_smpte_fill_lut(unsigned int ncolors, struct drm_color_lut *lut);
 
 enum util_fill_pattern util_pattern_enum(const char *name);
 
diff --git a/vc4/Makefile.sources b/vc4/Makefile.sources
deleted file mode 100644
index 8bf97ff1..00000000
--- a/vc4/Makefile.sources
+++ /dev/null
@@ -1,3 +0,0 @@
-LIBDRM_VC4_H_FILES := \
-	vc4_packet.h \
-	vc4_qpu_defines.h
diff --git a/xf86atomic.h b/xf86atomic.h
index efa47a77..c19e493b 100644
--- a/xf86atomic.h
+++ b/xf86atomic.h
@@ -108,7 +108,7 @@ static inline int atomic_add_unless(atomic_t *v, int add, int unless)
 	c = atomic_read(v);
 	while (c != unless && (old = atomic_cmpxchg(v, c, c + add)) != c)
 		c = old;
-	return c == unless;
+	return c != unless;
 }
 
 #endif
diff --git a/xf86drm.c b/xf86drm.c
index 5933e4bc..5f0eddc4 100644
--- a/xf86drm.c
+++ b/xf86drm.c
@@ -60,7 +60,6 @@
 #if HAVE_SYS_SYSCTL_H
 #include <sys/sysctl.h>
 #endif
-#include <math.h>
 #include <inttypes.h>
 
 #if defined(__FreeBSD__)
@@ -175,11 +174,15 @@ drmGetFormatModifierNameFromAmd(uint64_t modifier);
 static char *
 drmGetFormatModifierNameFromAmlogic(uint64_t modifier);
 
+static char *
+drmGetFormatModifierNameFromVivante(uint64_t modifier);
+
 static const struct drmVendorInfo modifier_format_vendor_table[] = {
     { DRM_FORMAT_MOD_VENDOR_ARM, drmGetFormatModifierNameFromArm },
     { DRM_FORMAT_MOD_VENDOR_NVIDIA, drmGetFormatModifierNameFromNvidia },
     { DRM_FORMAT_MOD_VENDOR_AMD, drmGetFormatModifierNameFromAmd },
     { DRM_FORMAT_MOD_VENDOR_AMLOGIC, drmGetFormatModifierNameFromAmlogic },
+    { DRM_FORMAT_MOD_VENDOR_VIVANTE, drmGetFormatModifierNameFromVivante },
 };
 
 #ifndef AFBC_FORMAT_MOD_MODE_VALUE_MASK
@@ -261,6 +264,7 @@ drmGetAfbcFormatModifierNameFromArm(uint64_t modifier, FILE *fp)
 static bool
 drmGetAfrcFormatModifierNameFromArm(uint64_t modifier, FILE *fp)
 {
+    bool scan_layout;
     for (unsigned int i = 0; i < 2; ++i) {
         uint64_t coding_unit_block =
           (modifier >> (i * 4)) & AFRC_FORMAT_MOD_CU_SIZE_MASK;
@@ -292,7 +296,7 @@ drmGetAfrcFormatModifierNameFromArm(uint64_t modifier, FILE *fp)
         }
     }
 
-    bool scan_layout =
+    scan_layout =
         (modifier & AFRC_FORMAT_MOD_LAYOUT_SCAN) == AFRC_FORMAT_MOD_LAYOUT_SCAN;
     if (scan_layout) {
         fprintf(fp, "SCAN");
@@ -473,6 +477,9 @@ drmGetFormatModifierNameFromAmd(uint64_t modifier)
     case AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS:
         str_tile_version = "GFX10_RBPLUS";
         break;
+    case AMD_FMT_MOD_TILE_VER_GFX11:
+        str_tile_version = "GFX11";
+        break;
     }
 
     if (str_tile_version) {
@@ -500,6 +507,9 @@ drmGetFormatModifierNameFromAmd(uint64_t modifier)
     case AMD_FMT_MOD_TILE_GFX9_64K_R_X:
         str_tile = "GFX9_64K_R_X";
         break;
+    case AMD_FMT_MOD_TILE_GFX11_256K_R_X:
+        str_tile = "GFX11_256K_R_X";
+        break;
     }
 
     if (str_tile)
@@ -546,6 +556,70 @@ drmGetFormatModifierNameFromAmlogic(uint64_t modifier)
     return mod_amlogic;
 }
 
+static char *
+drmGetFormatModifierNameFromVivante(uint64_t modifier)
+{
+    const char *color_tiling, *tile_status, *compression;
+    char *mod_vivante = NULL;
+
+    switch (modifier & VIVANTE_MOD_TS_MASK) {
+    case 0:
+        tile_status = "";
+        break;
+    case VIVANTE_MOD_TS_64_4:
+        tile_status = ",TS=64B_4";
+        break;
+    case VIVANTE_MOD_TS_64_2:
+        tile_status = ",TS=64B_2";
+        break;
+    case VIVANTE_MOD_TS_128_4:
+        tile_status = ",TS=128B_4";
+        break;
+    case VIVANTE_MOD_TS_256_4:
+        tile_status = ",TS=256B_4";
+        break;
+    default:
+        tile_status = ",TS=UNKNOWN";
+        break;
+    }
+
+    switch (modifier & VIVANTE_MOD_COMP_MASK) {
+    case 0:
+        compression = "";
+        break;
+    case VIVANTE_MOD_COMP_DEC400:
+        compression = ",COMP=DEC400";
+        break;
+    default:
+        compression = ",COMP=UNKNOWN";
+	break;
+    }
+
+    switch (modifier & ~VIVANTE_MOD_EXT_MASK) {
+    case 0:
+        color_tiling = "LINEAR";
+	break;
+    case DRM_FORMAT_MOD_VIVANTE_TILED:
+        color_tiling = "TILED";
+	break;
+    case DRM_FORMAT_MOD_VIVANTE_SUPER_TILED:
+        color_tiling = "SUPER_TILED";
+	break;
+    case DRM_FORMAT_MOD_VIVANTE_SPLIT_TILED:
+        color_tiling = "SPLIT_TILED";
+	break;
+    case DRM_FORMAT_MOD_VIVANTE_SPLIT_SUPER_TILED:
+        color_tiling = "SPLIT_SUPER_TILED";
+	break;
+    default:
+        color_tiling = "UNKNOWN";
+	break;
+    }
+
+    asprintf(&mod_vivante, "%s%s%s", color_tiling, tile_status, compression);
+    return mod_vivante;
+}
+
 static unsigned log2_int(unsigned x)
 {
     unsigned l;
@@ -754,8 +828,6 @@ static const char *drmGetDeviceName(int type)
     switch (type) {
     case DRM_NODE_PRIMARY:
         return DRM_DEV_NAME;
-    case DRM_NODE_CONTROL:
-        return DRM_CONTROL_DEV_NAME;
     case DRM_NODE_RENDER:
         return DRM_RENDER_DEV_NAME;
     }
@@ -848,7 +920,7 @@ wait_for_udev:
     }
 #endif
 
-    fd = open(buf, O_RDWR | O_CLOEXEC, 0);
+    fd = open(buf, O_RDWR | O_CLOEXEC);
     drmMsg("drmOpenDevice: open result is %d, (%s)\n",
            fd, fd < 0 ? strerror(errno) : "OK");
     if (fd >= 0)
@@ -868,7 +940,7 @@ wait_for_udev:
             chmod(buf, devmode);
         }
     }
-    fd = open(buf, O_RDWR | O_CLOEXEC, 0);
+    fd = open(buf, O_RDWR | O_CLOEXEC);
     drmMsg("drmOpenDevice: open result is %d, (%s)\n",
            fd, fd < 0 ? strerror(errno) : "OK");
     if (fd >= 0)
@@ -906,7 +978,7 @@ static int drmOpenMinor(int minor, int create, int type)
         return -EINVAL;
 
     sprintf(buf, dev_name, DRM_DIR_NAME, minor);
-    if ((fd = open(buf, O_RDWR | O_CLOEXEC, 0)) >= 0)
+    if ((fd = open(buf, O_RDWR | O_CLOEXEC)) >= 0)
         return fd;
     return -errno;
 }
@@ -951,8 +1023,6 @@ static int drmGetMinorBase(int type)
     switch (type) {
     case DRM_NODE_PRIMARY:
         return 0;
-    case DRM_NODE_CONTROL:
-        return 64;
     case DRM_NODE_RENDER:
         return 128;
     default:
@@ -973,8 +1043,6 @@ static int drmGetMinorType(int major, int minor)
         // If not in /dev/drm/ we have the type in the name
         if (sscanf(name, "dri/card%d\n", &id) >= 1)
            return DRM_NODE_PRIMARY;
-        else if (sscanf(name, "dri/control%d\n", &id) >= 1)
-           return DRM_NODE_CONTROL;
         else if (sscanf(name, "dri/renderD%d\n", &id) >= 1)
            return DRM_NODE_RENDER;
         return -1;
@@ -982,19 +1050,20 @@ static int drmGetMinorType(int major, int minor)
 
     minor = id;
 #endif
-    int type = minor >> 6;
-
-    if (minor < 0)
-        return -1;
+    char path[DRM_NODE_NAME_MAX];
+    const char *dev_name;
+    int i;
 
-    switch (type) {
-    case DRM_NODE_PRIMARY:
-    case DRM_NODE_CONTROL:
-    case DRM_NODE_RENDER:
-        return type;
-    default:
-        return -1;
+    for (i = DRM_NODE_PRIMARY; i < DRM_NODE_MAX; i++) {
+        dev_name = drmGetDeviceName(i);
+        if (!dev_name)
+           continue;
+        snprintf(path, sizeof(path), dev_name, DRM_DIR_NAME, minor);
+        if (!access(path, F_OK))
+           return i;
     }
+
+    return -1;
 }
 
 static const char *drmGetMinorName(int type)
@@ -1002,8 +1071,6 @@ static const char *drmGetMinorName(int type)
     switch (type) {
     case DRM_NODE_PRIMARY:
         return DRM_PRIMARY_MINOR_NAME;
-    case DRM_NODE_CONTROL:
-        return DRM_CONTROL_MINOR_NAME;
     case DRM_NODE_RENDER:
         return DRM_RENDER_MINOR_NAME;
     default:
@@ -1134,7 +1201,7 @@ static int drmOpenByName(const char *name, int type)
         int  retcode;
 
         sprintf(proc_name, "/proc/dri/%d/name", i);
-        if ((fd = open(proc_name, O_RDONLY, 0)) >= 0) {
+        if ((fd = open(proc_name, O_RDONLY)) >= 0) {
             retcode = read(fd, buf, sizeof(buf)-1);
             close(fd);
             if (retcode) {
@@ -1190,7 +1257,7 @@ drm_public int drmOpen(const char *name, const char *busid)
  *
  * \param name driver name. Not referenced if bus ID is supplied.
  * \param busid bus ID. Zero if not known.
- * \param type the device node type to open, PRIMARY, CONTROL or RENDER
+ * \param type the device node type to open, PRIMARY or RENDER
  *
  * \return a file descriptor on success, or a negative value on error.
  *
@@ -1223,7 +1290,7 @@ drm_public int drmOpenWithType(const char *name, const char *busid, int type)
 
 drm_public int drmOpenControl(int minor)
 {
-    return drmOpenMinor(minor, 0, DRM_NODE_CONTROL);
+    return -EINVAL;
 }
 
 drm_public int drmOpenRender(int minor)
@@ -3629,12 +3696,9 @@ static int get_sysctl_pci_bus_info(int maj, int min, drmPciBusInfoPtr info)
     switch (type) {
     case DRM_NODE_PRIMARY:
          break;
-    case DRM_NODE_CONTROL:
-         id -= 64;
-         break;
     case DRM_NODE_RENDER:
          id -= 128;
-          break;
+         break;
     }
     if (id < 0)
         return -EINVAL;
@@ -3746,10 +3810,6 @@ drm_public int drmDevicesEqual(drmDevicePtr a, drmDevicePtr b)
 
 static int drmGetNodeType(const char *name)
 {
-    if (strncmp(name, DRM_CONTROL_MINOR_NAME,
-        sizeof(DRM_CONTROL_MINOR_NAME ) - 1) == 0)
-        return DRM_NODE_CONTROL;
-
     if (strncmp(name, DRM_RENDER_MINOR_NAME,
         sizeof(DRM_RENDER_MINOR_NAME) - 1) == 0)
         return DRM_NODE_RENDER;
@@ -3891,7 +3951,7 @@ static int drmParsePciDeviceInfo(int maj, int min,
     if (get_sysctl_pci_bus_info(maj, min, &info) != 0)
         return -EINVAL;
 
-    fd = open("/dev/pci", O_RDONLY, 0);
+    fd = open("/dev/pci", O_RDONLY);
     if (fd < 0)
         return -errno;
 
@@ -4410,14 +4470,24 @@ process_device(drmDevicePtr *device, const char *d_name,
 {
     struct stat sbuf;
     char node[PATH_MAX + 1];
-    int node_type, subsystem_type;
+    int node_type, subsystem_type, written;
     unsigned int maj, min;
+    const int max_node_length = ALIGN(drmGetMaxNodeName(), sizeof(void *));
 
     node_type = drmGetNodeType(d_name);
     if (node_type < 0)
         return -1;
 
-    snprintf(node, PATH_MAX, "%s/%s", DRM_DIR_NAME, d_name);
+    written = snprintf(node, PATH_MAX, "%s/%s", DRM_DIR_NAME, d_name);
+    if (written < 0)
+        return -1;
+
+    /* anything longer than this will be truncated in drmDeviceAlloc.
+     * Account for NULL byte
+     */
+    if (written + 1 > max_node_length)
+        return -1;
+
     if (stat(node, &sbuf))
         return -1;
 
@@ -4524,6 +4594,8 @@ drm_public int drmGetDeviceFromDevId(dev_t find_rdev, uint32_t flags, drmDeviceP
     const char      *dev_name;
     int              node_type, subsystem_type;
     int              maj, min, n, ret;
+    const int        max_node_length = ALIGN(drmGetMaxNodeName(), sizeof(void *));
+    struct stat      sbuf;
 
     if (device == NULL)
         return -EINVAL;
@@ -4542,9 +4614,14 @@ drm_public int drmGetDeviceFromDevId(dev_t find_rdev, uint32_t flags, drmDeviceP
     if (!dev_name)
         return -EINVAL;
 
+    /* anything longer than this will be truncated in drmDeviceAlloc.
+     * Account for NULL byte
+     */
     n = snprintf(node, PATH_MAX, dev_name, DRM_DIR_NAME, min);
     if (n == -1 || n >= PATH_MAX)
       return -errno;
+    if (n + 1 > max_node_length)
+        return -EINVAL;
     if (stat(node, &sbuf))
         return -EINVAL;
 
@@ -4626,6 +4703,23 @@ drm_public int drmGetDeviceFromDevId(dev_t find_rdev, uint32_t flags, drmDeviceP
 #endif
 }
 
+drm_public int drmGetNodeTypeFromDevId(dev_t devid)
+{
+    int maj, min, node_type;
+
+    maj = major(devid);
+    min = minor(devid);
+
+    if (!drmNodeIsDRM(maj, min))
+        return -EINVAL;
+
+    node_type = drmGetMinorType(maj, min);
+    if (node_type == -1)
+        return -ENODEV;
+
+    return node_type;
+}
+
 /**
  * Get information about the opened drm device
  *
@@ -5043,6 +5137,20 @@ drm_public int drmSyncobjTransfer(int fd,
     return ret;
 }
 
+drm_public int drmSyncobjEventfd(int fd, uint32_t handle, uint64_t point, int ev_fd,
+                                 uint32_t flags)
+{
+    struct drm_syncobj_eventfd args;
+
+    memclear(args);
+    args.handle = handle;
+    args.point = point;
+    args.fd = ev_fd;
+    args.flags = flags;
+
+    return drmIoctl(fd, DRM_IOCTL_SYNCOBJ_EVENTFD, &args);
+}
+
 static char *
 drmGetFormatModifierFromSimpleTokens(uint64_t modifier)
 {
@@ -5105,3 +5213,43 @@ drmGetFormatModifierName(uint64_t modifier)
 
     return modifier_found;
 }
+
+/**
+ * Get a human-readable name for a DRM FourCC format.
+ *
+ * \param format The format.
+ * \return A malloc'ed string containing the format name. Caller is responsible
+ * for freeing it.
+ */
+drm_public char *
+drmGetFormatName(uint32_t format)
+{
+    char *str, code[5];
+    const char *be;
+    size_t str_size, i;
+
+    be = (format & DRM_FORMAT_BIG_ENDIAN) ? "_BE" : "";
+    format &= ~DRM_FORMAT_BIG_ENDIAN;
+
+    if (format == DRM_FORMAT_INVALID)
+        return strdup("INVALID");
+
+    code[0] = (char) ((format >> 0) & 0xFF);
+    code[1] = (char) ((format >> 8) & 0xFF);
+    code[2] = (char) ((format >> 16) & 0xFF);
+    code[3] = (char) ((format >> 24) & 0xFF);
+    code[4] = '\0';
+
+    /* Trim spaces at the end */
+    for (i = 3; i > 0 && code[i] == ' '; i--)
+        code[i] = '\0';
+
+    str_size = strlen(code) + strlen(be) + 1;
+    str = malloc(str_size);
+    if (!str)
+        return NULL;
+
+    snprintf(str, str_size, "%s%s", code, be);
+
+    return str;
+}
diff --git a/xf86drm.h b/xf86drm.h
index 1631396a..6d91dfbd 100644
--- a/xf86drm.h
+++ b/xf86drm.h
@@ -44,7 +44,7 @@ extern "C" {
 #endif
 
 #ifndef DRM_MAX_MINOR
-#define DRM_MAX_MINOR   16
+#define DRM_MAX_MINOR   64 /* deprecated */
 #endif
 
 #if defined(__linux__)
@@ -79,18 +79,18 @@ extern "C" {
 #ifdef __OpenBSD__
 #define DRM_DIR_NAME  "/dev"
 #define DRM_PRIMARY_MINOR_NAME  "drm"
-#define DRM_CONTROL_MINOR_NAME  "drmC"
+#define DRM_CONTROL_MINOR_NAME  "drmC" /* deprecated */
 #define DRM_RENDER_MINOR_NAME   "drmR"
 #else
 #define DRM_DIR_NAME  "/dev/dri"
 #define DRM_PRIMARY_MINOR_NAME  "card"
-#define DRM_CONTROL_MINOR_NAME  "controlD"
+#define DRM_CONTROL_MINOR_NAME  "controlD" /* deprecated */
 #define DRM_RENDER_MINOR_NAME   "renderD"
 #define DRM_PROC_NAME "/proc/dri/" /* For backward Linux compatibility */
 #endif
 
 #define DRM_DEV_NAME          "%s/" DRM_PRIMARY_MINOR_NAME "%d"
-#define DRM_CONTROL_DEV_NAME  "%s/" DRM_CONTROL_MINOR_NAME "%d"
+#define DRM_CONTROL_DEV_NAME  "%s/" DRM_CONTROL_MINOR_NAME "%d" /* deprecated */
 #define DRM_RENDER_DEV_NAME   "%s/" DRM_RENDER_MINOR_NAME  "%d"
 
 #define DRM_NODE_NAME_MAX \
@@ -98,7 +98,7 @@ extern "C" {
      + MAX3(sizeof(DRM_PRIMARY_MINOR_NAME), \
             sizeof(DRM_CONTROL_MINOR_NAME), \
             sizeof(DRM_RENDER_MINOR_NAME)) \
-     + sizeof("144") /* highest possible node number */ \
+     + sizeof("1048575") /* highest possible node number 2^MINORBITS - 1 */ \
      + 1) /* NULL-terminator */
 
 #define DRM_ERR_NO_DEVICE  (-1001)
@@ -596,14 +596,14 @@ extern int           drmAvailable(void);
 extern int           drmOpen(const char *name, const char *busid);
 
 #define DRM_NODE_PRIMARY 0
-#define DRM_NODE_CONTROL 1
+#define DRM_NODE_CONTROL 1 /* deprecated: never returned */
 #define DRM_NODE_RENDER  2
 #define DRM_NODE_MAX     3
 
 extern int           drmOpenWithType(const char *name, const char *busid,
                                      int type);
 
-extern int           drmOpenControl(int minor);
+extern int           drmOpenControl(int minor); /* deprecated: always fails */
 extern int           drmOpenRender(int minor);
 extern int           drmClose(int fd);
 extern drmVersionPtr drmGetVersion(int fd);
@@ -808,7 +808,7 @@ extern int drmHandleEvent(int fd, drmEventContextPtr evctx);
 extern char *drmGetDeviceNameFromFd(int fd);
 
 /* Improved version of drmGetDeviceNameFromFd which attributes for any type of
- * device/node - card, control or renderD.
+ * device/node - card or renderD.
  */
 extern char *drmGetDeviceNameFromFd2(int fd);
 extern int drmGetNodeTypeFromFd(int fd);
@@ -919,6 +919,18 @@ extern int drmGetDevices2(uint32_t flags, drmDevicePtr devices[], int max_device
 
 extern int drmGetDeviceFromDevId(dev_t dev_id, uint32_t flags, drmDevicePtr *device);
 
+/**
+ * Get the node type (DRM_NODE_PRIMARY or DRM_NODE_RENDER) from a device ID.
+ *
+ * Returns negative errno on error.
+ */
+extern int drmGetNodeTypeFromDevId(dev_t devid);
+
+/**
+ * Check if two drmDevice pointers represent the same DRM device.
+ *
+ * Returns 1 if the devices are equal, 0 otherwise.
+ */
 extern int drmDevicesEqual(drmDevicePtr a, drmDevicePtr b);
 
 extern int drmSyncobjCreate(int fd, uint32_t flags, uint32_t *handle);
@@ -947,6 +959,8 @@ extern int drmSyncobjTransfer(int fd,
 			      uint32_t dst_handle, uint64_t dst_point,
 			      uint32_t src_handle, uint64_t src_point,
 			      uint32_t flags);
+extern int drmSyncobjEventfd(int fd, uint32_t handle, uint64_t point, int ev_fd,
+                             uint32_t flags);
 
 extern char *
 drmGetFormatModifierVendor(uint64_t modifier);
@@ -954,6 +968,9 @@ drmGetFormatModifierVendor(uint64_t modifier);
 extern char *
 drmGetFormatModifierName(uint64_t modifier);
 
+extern char *
+drmGetFormatName(uint32_t format);
+
 #ifndef fourcc_mod_get_vendor
 #define fourcc_mod_get_vendor(modifier) \
        (((modifier) >> 56) & 0xff)
diff --git a/xf86drmMode.c b/xf86drmMode.c
index 87e96603..a4873a0f 100644
--- a/xf86drmMode.c
+++ b/xf86drmMode.c
@@ -320,6 +320,16 @@ drm_public int drmModeRmFB(int fd, uint32_t bufferId)
 	return DRM_IOCTL(fd, DRM_IOCTL_MODE_RMFB, &bufferId);
 }
 
+drm_public int drmModeCloseFB(int fd, uint32_t buffer_id)
+{
+	struct drm_mode_closefb closefb;
+
+	memclear(closefb);
+	closefb.fb_id = buffer_id;
+
+	return DRM_IOCTL(fd, DRM_IOCTL_MODE_CLOSEFB, &closefb);
+}
+
 drm_public drmModeFBPtr drmModeGetFB(int fd, uint32_t buf)
 {
 	struct drm_mode_fb_cmd info;
@@ -610,6 +620,29 @@ drm_public drmModeConnectorPtr drmModeGetConnectorCurrent(int fd, uint32_t conne
 	return _drmModeGetConnector(fd, connector_id, 0);
 }
 
+drm_public uint32_t drmModeConnectorGetPossibleCrtcs(int fd,
+                                                     const drmModeConnector *connector)
+{
+	drmModeEncoder *encoder;
+	int i;
+	uint32_t possible_crtcs;
+
+	possible_crtcs = 0;
+	for (i = 0; i < connector->count_encoders; i++) {
+		encoder = drmModeGetEncoder(fd, connector->encoders[i]);
+		if (!encoder) {
+			return 0;
+		}
+
+		possible_crtcs |= encoder->possible_crtcs;
+		drmModeFreeEncoder(encoder);
+	}
+
+	if (possible_crtcs == 0)
+		errno = ENOENT;
+	return possible_crtcs;
+}
+
 drm_public int drmModeAttachMode(int fd, uint32_t connector_id, drmModeModeInfoPtr mode_info)
 {
 	struct drm_mode_mode_cmd res;
@@ -981,8 +1014,8 @@ drm_public int drmModeCrtcGetGamma(int fd, uint32_t crtc_id, uint32_t size,
 }
 
 drm_public int drmModeCrtcSetGamma(int fd, uint32_t crtc_id, uint32_t size,
-								   uint16_t *red, uint16_t *green,
-								   uint16_t *blue)
+								   const uint16_t *red, const uint16_t *green,
+								   const uint16_t *blue)
 {
 	struct drm_mode_crtc_lut l;
 
@@ -1348,7 +1381,7 @@ drm_public drmModeAtomicReqPtr drmModeAtomicAlloc(void)
 	return req;
 }
 
-drm_public drmModeAtomicReqPtr drmModeAtomicDuplicate(drmModeAtomicReqPtr old)
+drm_public drmModeAtomicReqPtr drmModeAtomicDuplicate(const drmModeAtomicReqPtr old)
 {
 	drmModeAtomicReqPtr new;
 
@@ -1378,7 +1411,7 @@ drm_public drmModeAtomicReqPtr drmModeAtomicDuplicate(drmModeAtomicReqPtr old)
 }
 
 drm_public int drmModeAtomicMerge(drmModeAtomicReqPtr base,
-                                  drmModeAtomicReqPtr augment)
+                                  const drmModeAtomicReqPtr augment)
 {
 	uint32_t i;
 
@@ -1411,7 +1444,7 @@ drm_public int drmModeAtomicMerge(drmModeAtomicReqPtr base,
 	return 0;
 }
 
-drm_public int drmModeAtomicGetCursor(drmModeAtomicReqPtr req)
+drm_public int drmModeAtomicGetCursor(const drmModeAtomicReqPtr req)
 {
 	if (!req)
 		return -EINVAL;
@@ -1480,7 +1513,7 @@ static int sort_req_list(const void *misc, const void *other)
 		return first->cursor - second->cursor;
 }
 
-drm_public int drmModeAtomicCommit(int fd, drmModeAtomicReqPtr req,
+drm_public int drmModeAtomicCommit(int fd, const drmModeAtomicReqPtr req,
                                    uint32_t flags, void *user_data)
 {
 	drmModeAtomicReqPtr sorted;
@@ -1747,3 +1780,105 @@ drm_public void drmModeFreeFB2(drmModeFB2Ptr ptr)
 {
 	drmFree(ptr);
 }
+
+drm_public const char *
+drmModeGetConnectorTypeName(uint32_t connector_type)
+{
+	/* Keep the strings in sync with the kernel's drm_connector_enum_list in
+	 * drm_connector.c. */
+	switch (connector_type) {
+	case DRM_MODE_CONNECTOR_Unknown:
+		return "Unknown";
+	case DRM_MODE_CONNECTOR_VGA:
+		return "VGA";
+	case DRM_MODE_CONNECTOR_DVII:
+		return "DVI-I";
+	case DRM_MODE_CONNECTOR_DVID:
+		return "DVI-D";
+	case DRM_MODE_CONNECTOR_DVIA:
+		return "DVI-A";
+	case DRM_MODE_CONNECTOR_Composite:
+		return "Composite";
+	case DRM_MODE_CONNECTOR_SVIDEO:
+		return "SVIDEO";
+	case DRM_MODE_CONNECTOR_LVDS:
+		return "LVDS";
+	case DRM_MODE_CONNECTOR_Component:
+		return "Component";
+	case DRM_MODE_CONNECTOR_9PinDIN:
+		return "DIN";
+	case DRM_MODE_CONNECTOR_DisplayPort:
+		return "DP";
+	case DRM_MODE_CONNECTOR_HDMIA:
+		return "HDMI-A";
+	case DRM_MODE_CONNECTOR_HDMIB:
+		return "HDMI-B";
+	case DRM_MODE_CONNECTOR_TV:
+		return "TV";
+	case DRM_MODE_CONNECTOR_eDP:
+		return "eDP";
+	case DRM_MODE_CONNECTOR_VIRTUAL:
+		return "Virtual";
+	case DRM_MODE_CONNECTOR_DSI:
+		return "DSI";
+	case DRM_MODE_CONNECTOR_DPI:
+		return "DPI";
+	case DRM_MODE_CONNECTOR_WRITEBACK:
+		return "Writeback";
+	case DRM_MODE_CONNECTOR_SPI:
+		return "SPI";
+	case DRM_MODE_CONNECTOR_USB:
+		return "USB";
+	default:
+		return NULL;
+	}
+}
+
+drm_public int
+drmModeCreateDumbBuffer(int fd, uint32_t width, uint32_t height, uint32_t bpp,
+                        uint32_t flags, uint32_t *handle, uint32_t *pitch,
+                        uint64_t *size)
+{
+	int ret;
+	struct drm_mode_create_dumb create = {
+		.width = width,
+		.height = height,
+		.bpp = bpp,
+		.flags = flags,
+	};
+
+	ret = DRM_IOCTL(fd, DRM_IOCTL_MODE_CREATE_DUMB, &create);
+	if (ret != 0)
+		return ret;
+
+	*handle = create.handle;
+	*pitch = create.pitch;
+	*size = create.size;
+	return 0;
+}
+
+drm_public int
+drmModeDestroyDumbBuffer(int fd, uint32_t handle)
+{
+	struct drm_mode_destroy_dumb destroy = {
+		.handle = handle,
+	};
+
+	return DRM_IOCTL(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &destroy);
+}
+
+drm_public int
+drmModeMapDumbBuffer(int fd, uint32_t handle, uint64_t *offset)
+{
+	int ret;
+	struct drm_mode_map_dumb map = {
+		.handle = handle,
+	};
+
+	ret = DRM_IOCTL(fd, DRM_IOCTL_MODE_MAP_DUMB, &map);
+	if (ret != 0)
+		return ret;
+
+	*offset = map.offset;
+	return 0;
+}
diff --git a/xf86drmMode.h b/xf86drmMode.h
index 19bf91dd..08487887 100644
--- a/xf86drmMode.h
+++ b/xf86drmMode.h
@@ -314,6 +314,13 @@ int drmModeAddFB2WithModifiers(int fd, uint32_t width, uint32_t height,
  */
 extern int drmModeRmFB(int fd, uint32_t bufferId);
 
+/**
+ * Close a framebuffer.
+ *
+ * Same as drmModeRmFB(), except it doesn't implicitly disable planes and CRTCs.
+ */
+extern int drmModeCloseFB(int fd, uint32_t buffer_id);
+
 /**
  * Mark a region of a framebuffer as dirty.
  */
@@ -380,6 +387,19 @@ extern drmModeConnectorPtr drmModeGetConnector(int fd,
 extern drmModeConnectorPtr drmModeGetConnectorCurrent(int fd,
 						      uint32_t connector_id);
 
+/**
+ * Get a bitmask of CRTCs a connector is compatible with.
+ *
+ * The bits reference CRTC indices. If the n-th CRTC is compatible with the
+ * connector, the n-th bit will be set. The indices are taken from the array
+ * returned by drmModeGetResources(). The indices are different from the object
+ * IDs.
+ *
+ * Zero is returned on error.
+ */
+extern uint32_t drmModeConnectorGetPossibleCrtcs(int fd,
+                                                 const drmModeConnector *connector);
+
 /**
  * Attaches the given mode to an connector.
  */
@@ -403,7 +423,7 @@ extern int drmModeConnectorSetProperty(int fd, uint32_t connector_id, uint32_t p
 extern int drmCheckModesettingSupported(const char *busid);
 
 extern int drmModeCrtcSetGamma(int fd, uint32_t crtc_id, uint32_t size,
-			       uint16_t *red, uint16_t *green, uint16_t *blue);
+			       const uint16_t *red, const uint16_t *green, const uint16_t *blue);
 extern int drmModeCrtcGetGamma(int fd, uint32_t crtc_id, uint32_t size,
 			       uint16_t *red, uint16_t *green, uint16_t *blue);
 extern int drmModePageFlip(int fd, uint32_t crtc_id, uint32_t fb_id,
@@ -433,18 +453,18 @@ extern int drmModeObjectSetProperty(int fd, uint32_t object_id,
 typedef struct _drmModeAtomicReq drmModeAtomicReq, *drmModeAtomicReqPtr;
 
 extern drmModeAtomicReqPtr drmModeAtomicAlloc(void);
-extern drmModeAtomicReqPtr drmModeAtomicDuplicate(drmModeAtomicReqPtr req);
+extern drmModeAtomicReqPtr drmModeAtomicDuplicate(const drmModeAtomicReqPtr req);
 extern int drmModeAtomicMerge(drmModeAtomicReqPtr base,
-			      drmModeAtomicReqPtr augment);
+			      const drmModeAtomicReqPtr augment);
 extern void drmModeAtomicFree(drmModeAtomicReqPtr req);
-extern int drmModeAtomicGetCursor(drmModeAtomicReqPtr req);
+extern int drmModeAtomicGetCursor(const drmModeAtomicReqPtr req);
 extern void drmModeAtomicSetCursor(drmModeAtomicReqPtr req, int cursor);
 extern int drmModeAtomicAddProperty(drmModeAtomicReqPtr req,
 				    uint32_t object_id,
 				    uint32_t property_id,
 				    uint64_t value);
 extern int drmModeAtomicCommit(int fd,
-			       drmModeAtomicReqPtr req,
+			       const drmModeAtomicReqPtr req,
 			       uint32_t flags,
 			       void *user_data);
 
@@ -475,6 +495,47 @@ extern drmModeObjectListPtr drmModeGetLease(int fd);
 
 extern int drmModeRevokeLease(int fd, uint32_t lessee_id);
 
+/**
+ * Get a string describing a connector type.
+ *
+ * NULL is returned if the connector type is unsupported. Callers should handle
+ * this gracefully, e.g. by falling back to "Unknown" or printing the raw value.
+ */
+extern const char *
+drmModeGetConnectorTypeName(uint32_t connector_type);
+
+/**
+ * Create a dumb buffer.
+ *
+ * Given a width, height and bits-per-pixel, the kernel will return a buffer
+ * handle, pitch and size. The flags must be zero.
+ *
+ * Returns 0 on success, negative errno on error.
+ */
+extern int
+drmModeCreateDumbBuffer(int fd, uint32_t width, uint32_t height, uint32_t bpp,
+                        uint32_t flags, uint32_t *handle, uint32_t *pitch,
+                        uint64_t *size);
+
+/**
+ * Destroy a dumb buffer.
+ *
+ * Returns 0 on success, negative errno on error.
+ */
+extern int
+drmModeDestroyDumbBuffer(int fd, uint32_t handle);
+
+/**
+ * Prepare a dumb buffer for mapping.
+ *
+ * The kernel returns an offset which can be used as an argument to mmap(2) on
+ * the DRM FD.
+ *
+ * Returns 0 on success, negative errno on error.
+ */
+extern int
+drmModeMapDumbBuffer(int fd, uint32_t handle, uint64_t *offset);
+
 #if defined(__cplusplus)
 }
 #endif
```

