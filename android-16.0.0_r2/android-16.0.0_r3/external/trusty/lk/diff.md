```diff
diff --git a/arch/arm64/asm.S b/arch/arm64/asm.S
index 4a6ad835..d8acd257 100644
--- a/arch/arm64/asm.S
+++ b/arch/arm64/asm.S
@@ -125,20 +125,20 @@ FUNCTION(arm64_elX_to_el1)
 
 .confEL1:
     /* disable EL2 coprocessor traps */
-    mov x0, #0x33ff
-    msr cptr_el2, x0
+    mov x4, #0x33ff
+    msr cptr_el2, x4
 
     /* set EL1 to 64bit */
-    mov x0, #(1<<31)
-    msr hcr_el2, x0
+    mov x4, #(1<<31)
+    msr hcr_el2, x4
 
     /* disable EL1 FPU traps */
-    mov x0, #(0b11<<20)
-    msr cpacr_el1, x0
+    mov x4, #(0b11<<20)
+    msr cpacr_el1, x4
 
     /* set up the EL1 bounce interrupt */
-    mov x0, sp
-    msr sp_el1, x0
+    mov x4, sp
+    msr sp_el1, x4
 
     isb
     eret
diff --git a/dev/virtio/vsock-rust/rules.mk b/dev/virtio/vsock-rust/rules.mk
index a60b1ac8..a9c73959 100644
--- a/dev/virtio/vsock-rust/rules.mk
+++ b/dev/virtio/vsock-rust/rules.mk
@@ -8,6 +8,7 @@ MODULE_EXPORT_INCLUDES += \
 	$(LOCAL_DIR)/include
 
 MODULE_LIBRARY_DEPS := \
+	trusty/kernel/lib/rand/rust \
 	trusty/user/base/lib/liballoc-rust \
 	trusty/user/base/lib/trusty-std \
 	$(call FIND_CRATE,cfg-if) \
@@ -62,6 +63,7 @@ endif
 ifeq (true,$(call TOBOOL,$(TRUSTY_VM_INCLUDE_KEYMINT)))
 MODULE_RUSTFLAGS += \
 	--cfg 'feature="keymint"' \
+	--cfg 'feature="keymint_commservice"' \
 
 endif
 ifeq (true,$(call TOBOOL,$(TRUSTY_VM_INCLUDE_SECURE_STORAGE_HAL)))
@@ -73,8 +75,16 @@ ifeq (true,$(call TOBOOL,$(TRUSTY_VM_INCLUDE_AUTHMGR)))
 MODULE_RUSTFLAGS += \
 	--cfg 'feature="authmgr"' \
 
+endif
+ifeq (true,$(call TOBOOL,$(TRUSTY_VM_INCLUDE_VINTF_TA)))
+MODULE_RUSTFLAGS += \
+	--cfg 'feature="vintf_ta"' \
+
 endif
 
+ifeq (true,$(call TOBOOL,$(TRUSTY_VM_ENABLE_TIPC_VSOCK_AUTHMGR)))
+MODULE_RUSTFLAGS += --cfg 'feature="tipc_vsock_authmgr"'
+endif
 
 MODULE_RUST_USE_CLIPPY := true
 
diff --git a/dev/virtio/vsock-rust/src/pci.rs b/dev/virtio/vsock-rust/src/pci.rs
index 70e4c640..d5f9ec83 100644
--- a/dev/virtio/vsock-rust/src/pci.rs
+++ b/dev/virtio/vsock-rust/src/pci.rs
@@ -121,7 +121,7 @@ impl TrustyHal {
 
                 let driver: VirtIOSocket<TrustyHal, SomeTransport, 4096> =
                     VirtIOSocket::new(transport)?;
-                vsock_init(driver)?;
+                vsock_init(driver, None)?;
             }
         }
         Ok(())
diff --git a/dev/virtio/vsock-rust/src/vsock.rs b/dev/virtio/vsock-rust/src/vsock.rs
index 71b1061c..402b83e5 100644
--- a/dev/virtio/vsock-rust/src/vsock.rs
+++ b/dev/virtio/vsock-rust/src/vsock.rs
@@ -42,6 +42,7 @@ use log::error;
 use log::info;
 use log::warn;
 
+use rand::rand_get_bytes;
 use rust_support::handle::IPC_HANDLE_POLL_HUP;
 use rust_support::handle::IPC_HANDLE_POLL_MSG;
 use rust_support::handle::IPC_HANDLE_POLL_READY;
@@ -50,18 +51,23 @@ use rust_support::ipc::iovec_kern;
 use rust_support::ipc::ipc_get_msg;
 use rust_support::ipc::ipc_msg_info;
 use rust_support::ipc::ipc_msg_kern;
+use rust_support::ipc::ipc_port_accept;
 use rust_support::ipc::ipc_port_connect_async;
+use rust_support::ipc::ipc_port_create;
+use rust_support::ipc::ipc_port_publish;
 use rust_support::ipc::ipc_put_msg;
 use rust_support::ipc::ipc_read_msg;
 use rust_support::ipc::ipc_send_msg;
 use rust_support::ipc::zero_uuid;
 use rust_support::ipc::IPC_CONNECT_WAIT_FOR_PORT;
+use rust_support::ipc::IPC_PORT_ALLOW_TA_CONNECT;
 use rust_support::ipc::IPC_PORT_PATH_MAX;
 use rust_support::sync::Mutex;
 use rust_support::thread;
 use rust_support::thread::sleep;
 use rust_support::thread::Builder;
 use rust_support::thread::Priority;
+use rust_support::uuid::Uuid;
 use virtio_drivers_and_devices::device::socket::SocketError;
 use virtio_drivers_and_devices::device::socket::VirtIOSocket;
 use virtio_drivers_and_devices::device::socket::VsockAddr;
@@ -111,7 +117,7 @@ macro_rules! comm_port_feature_enable {
 //
 // Each tipc port name must be shorter than IPC_PORT_PATH_MAX.
 comm_port_feature_enable! {
-    PORT_MAP[8] = {
+    PORT_MAP[10] = {
         {port_name: c"com.android.trusty.authmgr", feature_name: "authmgr"},
         {port_name: c"com.android.trusty.hwcryptooperations", feature_name: "hwcrypto_hal"},
         {port_name: c"com.android.trusty.rust.hwcryptohal.V1", feature_name: "hwcrypto_hal"},
@@ -120,9 +126,52 @@ comm_port_feature_enable! {
         {port_name: c"com.android.trusty.storage.proxy", feature_name: "securestorage_hal"},
         {port_name: c"com.android.trusty.gatekeeper", feature_name: "gatekeeper"},
         {port_name: c"com.android.trusty.keymint", feature_name: "keymint"},
+        {port_name: c"com.android.trusty.vintf", feature_name: "vintf_ta"},
+        {port_name: c"com.android.trusty.keymint.commservice", feature_name: "keymint_commservice"},
     }
 }
 
+struct TipcToVsockMapping {
+    /// Local port name to listen on.
+    name: &'static CStr,
+
+    /// Secure partition ID to connect to using virtio-msg-ffa,
+    /// or `None` to use any other transport.
+    sp_id: Option<u16>,
+
+    /// Destination address to connect to.
+    addr: VsockAddr,
+
+    /// List of allowed UUIDs that can connect to this port.
+    /// All clients are allowed if this list is empty.
+    allowed_uuids: &'static [Uuid],
+}
+
+#[allow(dead_code)]
+const TRUSTY_SP_ID: u16 = 0x8001u16;
+
+const TIPC_TO_VSOCK_MAPPINGS: &[TipcToVsockMapping] = &[
+    #[cfg(TEST_BUILD)]
+    TipcToVsockMapping {
+        name: c"com.android.trusty.vsock.forwarder",
+        sp_id: Some(TRUSTY_SP_ID),
+        addr: VsockAddr { cid: 2, port: 0 },
+        allowed_uuids: &[],
+    },
+    #[cfg(feature = "tipc_vsock_authmgr")]
+    TipcToVsockMapping {
+        name: c"ahss.authmgr.IAuthManagerAuthorization/default.bnd",
+        sp_id: Some(TRUSTY_SP_ID),
+        addr: VsockAddr { cid: 2, port: 1 },
+        allowed_uuids: &[Uuid::new(
+            0x9b3c1e9e,
+            0x1808,
+            0x4b98,
+            [0x8f, 0xa9, 0x85, 0x92, 0xdf, 0xf3, 0xa3, 0x37],
+        )],
+    },
+];
+
 #[allow(dead_code)]
 #[derive(Clone, Copy, Debug, Default, PartialEq)]
 enum VsockConnectionState {
@@ -305,6 +354,7 @@ fn vsock_connection_close(c: &mut VsockConnection, action: ConnectionStateAction
     if c.state == VsockConnectionState::Active
         || c.state == VsockConnectionState::TipcConnecting
         || c.state == VsockConnectionState::TipcSendBlocked
+        || c.state == VsockConnectionState::TipcOnly
     {
         // The handle set owns the only reference we have to the handle and
         // handle_set_wait might have already returned a pointer to c
@@ -347,6 +397,11 @@ where
         }
     }
 
+    fn port_is_listening(&self, port: u32) -> bool {
+        // We listen on ports in the range 0..PORT_MAP.len()
+        port < PORT_MAP.len().try_into().unwrap()
+    }
+
     fn vsock_rx_op_request(&self, peer: VsockAddr, local: VsockAddr) -> Result<(), Error> {
         debug!("dst_port {}, src_port {}", local.port, peer.port);
 
@@ -415,6 +470,132 @@ where
         self.vsock_connect_tipc(c)
     }
 
+    fn create_tipc_ports(&self, sp_id: Option<u16>) -> [HandleRef; TIPC_TO_VSOCK_MAPPINGS.len()] {
+        let mut port_hrefs: [HandleRef; TIPC_TO_VSOCK_MAPPINGS.len()] = Default::default();
+        for (port, phref) in TIPC_TO_VSOCK_MAPPINGS.iter().zip(port_hrefs.iter_mut()) {
+            if port.sp_id != sp_id {
+                continue;
+            }
+
+            // Safety:
+            // - `sid` is a valid uuid because we use a bindgen'd constant
+            // - `path` points to a null-terminated C-string. The null byte was appended by
+            //   `CString::new`.
+            // - `num_recv_bufs` is a primitive value.
+            // - `recv_buf_size` is a primitive value.
+            // - `flags` contains a flag value accepted by the callee
+            // - `phandle_ptr` points to memory that the kernel can store a pointer into
+            //   after the callee returns.
+            let ret = unsafe {
+                ipc_port_create(
+                    &zero_uuid,
+                    port.name.as_ptr(),
+                    1,
+                    PAGE_SIZE,
+                    IPC_PORT_ALLOW_TA_CONNECT,
+                    &raw mut (*phref.as_mut_ptr()).handle,
+                )
+            };
+            if ret != 0 {
+                warn!("failed to create {:?}, remote {:?}, err {ret}", port.name, port.addr);
+                continue;
+            }
+
+            // Safety:
+            // - `phandle` is a valid port handle from ipc_port_create
+            let ret = unsafe { ipc_port_publish(phref.handle()) };
+            if ret != 0 {
+                warn!("failed to publish {:?}, remote {:?}, err {ret}", port.name, port.addr);
+                phref.handle_close();
+                continue;
+            }
+
+            phref.set_emask(!0);
+            if let Err(e) = self.handle_set.attach(phref) {
+                warn!("failed to attach port {:?}, remote {:?}, err {e}", port.name, port.addr);
+                phref.handle_close();
+                continue;
+            };
+
+            debug!("tipc to vsock mapping enabled on port {:?}", port.name);
+        }
+
+        port_hrefs
+    }
+
+    fn tipc_connect_vsock(
+        &self,
+        port: &TipcToVsockMapping,
+        href: &mut HandleRef,
+    ) -> Result<VsockConnection, Error> {
+        debug!("got tipc connection on {:?}", port.name);
+
+        // Pick a random unused 32-bit source port; the probability
+        // of collision should be pretty low if we pick randomly.
+        let mut cm = self.connection_manager.lock();
+        let mut src_port;
+        loop {
+            let mut src_port_bytes = [0; 4];
+            rand_get_bytes(&mut src_port_bytes[..]);
+            src_port = u32::from_ne_bytes(src_port_bytes);
+            if self.port_is_listening(src_port) {
+                // Don't use listening port numbers for outgoing connections
+                // to avoid conflicts with incoming connections.
+                continue;
+            }
+
+            match cm.connect(port.addr, src_port) {
+                Ok(()) => break,
+                Err(VirtioError::SocketDeviceError(SocketError::ConnectionExists)) => continue,
+                Err(e) => return Err(Error::Virtio(e)),
+            }
+        }
+
+        let mut c = VsockConnection::new(port.addr, src_port);
+        c.tipc_port_name = Some(port.name.to_owned());
+        c.state = VsockConnectionState::TipcOnly;
+
+        let mut peer_uuid_ptr = core::ptr::null();
+        // Safety:
+        // - `phandle` is a valid port from href
+        // - `chandle` is a zeroed HandleRef from c
+        // - `peer` is the zero-initialized pointer from above
+        let ret = unsafe {
+            ipc_port_accept(
+                href.handle(),
+                &raw mut (*c.href.as_mut_ptr()).handle,
+                &raw mut peer_uuid_ptr,
+            )
+        };
+        if ret < 0 {
+            error!("failed to accept connection on {:?}: {ret} ", port.name);
+            let _ = cm.force_close(c.peer, c.local_port);
+            LkError::from_lk(ret)?;
+        }
+
+        debug_assert!(!peer_uuid_ptr.is_null());
+        // Safety: `peer_uuid` is non-null and should point to a valid UUID by now
+        let peer_uuid = unsafe { Uuid(*peer_uuid_ptr) };
+        if !port.allowed_uuids.is_empty() && !port.allowed_uuids.contains(&peer_uuid) {
+            error!("client {:?} not allowed on {:?}: {ret} ", peer_uuid, port.name);
+            c.href.handle_close();
+            let _ = cm.force_close(c.peer, c.local_port);
+            return Err(LkError::ERR_NOT_ALLOWED.into());
+        }
+
+        // Initialize the cookie here so vsock_connection_lookup_cookie works
+        // correctly past this point. See comment in vsock_connect_tipc w.r.t.
+        // the choice of what to use as the cookie.
+        let cookie = c.href.as_mut_ptr() as *mut c_void;
+        c.href.set_cookie(cookie);
+        c.href.set_emask(!0);
+        c.href.set_id(c.peer.port);
+
+        debug!("accepted tipc connection on {:?}", port.name);
+
+        Ok(c)
+    }
+
     fn vsock_connect_tipc(&self, c: &mut VsockConnection) -> Result<(), Error> {
         let port_name = c.tipc_port_name.as_ref().expect("tipc port name has been set");
         // invariant: port_name.count_bytes() + 1 <= IPC_PORT_PATH_MAX
@@ -563,7 +744,25 @@ where
                 }
             }
             VsockEventType::Connected => {
-                panic!("outbound connections not supported");
+                debug!("connected destination: {destination:?}");
+
+                let connections = &mut *device.connections.lock();
+                let lp = destination.port;
+                let _ = vsock_connection_lookup_peer(connections, source, lp, |connection| {
+                    debug_assert!(connection.state == VsockConnectionState::TipcOnly);
+
+                    if let Err(e) = device.handle_set.attach(&mut connection.href) {
+                        error!("failed to attach connection: {:?}", e);
+                        device.vsock_send_reset(connection.peer, connection.local_port);
+                        return ConnectionStateAction::Remove;
+                    }
+
+                    connection.state = VsockConnectionState::Active;
+                    ConnectionStateAction::None
+                })
+                .inspect_err(|_| {
+                    warn!("got packet for unknown connection");
+                });
             }
             VsockEventType::Received { length } => {
                 debug!("recv destination: {destination:?}");
@@ -634,10 +833,13 @@ where
     }
 }
 
-pub(crate) fn vsock_tx_loop<M>(device: Arc<VsockDevice<M>>) -> Result<(), Error>
+pub(crate) fn vsock_tx_loop<M>(device: Arc<VsockDevice<M>>, sp_id: Option<u16>) -> Result<(), Error>
 where
     M: VsockManager,
 {
+    debug!("starting vsock_tx_loop");
+
+    let mut port_hrefs = device.create_tipc_ports(sp_id);
     let mut timeout = Duration::MAX;
     let ten_secs = Duration::from_secs(10);
     let mut tx_buffer = vec![0u8; PAGE_SIZE].into_boxed_slice();
@@ -668,8 +870,9 @@ where
             continue;
         }
 
+        let connections = &mut *device.connections.lock();
         let cookie = href.cookie();
-        let _ = vsock_connection_lookup_cookie(&mut device.connections.lock(), cookie, |c| {
+        let _ = vsock_connection_lookup_cookie(connections, cookie, |c| {
             if href.id() != c.href.id() {
                 panic!(
                     "unexpected id {:?} != {:?} for connection {}",
@@ -775,6 +978,20 @@ where
             ConnectionStateAction::None
         })
         .inspect_err(|_| {
+            if let Some(idx) =
+                port_hrefs.iter_mut().position(|phref| phref.handle() == href.handle())
+            {
+                if href.emask() & IPC_HANDLE_POLL_READY != 0 {
+                    match device.tipc_connect_vsock(&TIPC_TO_VSOCK_MAPPINGS[idx], &mut href) {
+                        Ok(c) => connections.push(c),
+                        Err(e) => error!("failed to accept tipc connection {e:?})"),
+                    }
+                } else if href.emask() != 0 {
+                    warn!("unexpected port emask {:x}", href.emask());
+                }
+                return;
+            }
+
             warn!("got event for non-existent remote {}, was it closed?", href.id());
         });
         href.handle_decref();
@@ -783,6 +1000,7 @@ where
 
 pub(crate) fn vsock_init<T: Transport + 'static + Send, H: Hal + 'static>(
     driver: VirtIOSocket<H, T, 4096>,
+    sp_id: Option<u16>,
 ) -> Result<(), Error> {
     let manager = VsockConnectionManager::new_with_capacity(driver, 4096);
     let device_for_rx = Arc::new(VsockDevice::new(manager));
@@ -806,7 +1024,7 @@ pub(crate) fn vsock_init<T: Transport + 'static + Send, H: Hal + 'static>(
         .priority(Priority::HIGH)
         .stack_size(stack_size)
         .spawn(move || {
-            let ret = vsock_tx_loop(device_for_tx);
+            let ret = vsock_tx_loop(device_for_tx, sp_id);
             error!("vsock_tx_loop returned {:?}", ret);
             ret.err().unwrap_or(LkError::NO_ERROR.into()).into_c()
         })
diff --git a/engine.mk b/engine.mk
index a04c5f16..95b9a269 100644
--- a/engine.mk
+++ b/engine.mk
@@ -260,6 +260,16 @@ GLOBAL_KERNEL_RUSTFLAGS += -Z branch-protection=pac-ret
 endif
 endif
 
+# add some automatic rust configuration flags
+GLOBAL_SHARED_RUSTFLAGS += \
+	--cfg='PLAT_$(call normalize-rust-cfg,$(PLATFORM))' \
+	--cfg='TARGET_$(call normalize-rust-cfg,$(TARGET))'
+
+# Add configuration flag if this is a test build
+ifeq (true,$(call TOBOOL,$(TEST_BUILD)))
+GLOBAL_SHARED_RUSTFLAGS += --cfg='TEST_BUILD'
+endif
+
 ifneq ($(GLOBAL_COMPILEFLAGS),)
 $(error Setting GLOBAL_COMPILEFLAGS directly from project or platform makefiles is no longer supported. Please use either GLOBAL_SHARED_COMPILEFLAGS or GLOBAL_KERNEL_COMPILEFLAGS.)
 endif
@@ -320,16 +330,6 @@ GLOBAL_DEFINES += \
 	LK_LOGLEVEL_RUST=$(LOG_LEVEL_KERNEL_RUST) \
 	TLOG_LVL_DEFAULT=$$(($(LOG_LEVEL_USER)+2)) \
 
-# add some automatic rust configuration flags
-GLOBAL_SHARED_RUSTFLAGS += \
-	--cfg='PLAT_$(call normalize-rust-cfg,$(PLATFORM))' \
-	--cfg='TARGET_$(call normalize-rust-cfg,$(TARGET))'
-
-# Add configuration flag if this is a test build
-ifeq (true,$(call TOBOOL,$(TEST_BUILD)))
-GLOBAL_SHARED_RUSTFLAGS += --cfg='TEST_BUILD'
-endif
-
 GLOBAL_USER_INCLUDES += $(addsuffix /arch/$(ARCH)/include,$(LKINC))
 
 # test build?
diff --git a/kernel/mutex.c b/kernel/mutex.c
index 0a409e85..5e0d5fdd 100644
--- a/kernel/mutex.c
+++ b/kernel/mutex.c
@@ -35,6 +35,21 @@
 #include <assert.h>
 #include <err.h>
 #include <kernel/thread.h>
+#include <lk/init.h>
+
+static bool mutex_threading_ready;
+
+/* mutex_threading_ready is currently only used from a DEBUG_ASSERT */
+#if LK_DEBUGLEVEL > 1
+
+static void mutex_threading_ready_init_func(uint level)
+{
+    mutex_threading_ready = true;
+}
+
+LK_INIT_HOOK(mutex_threading_ready, mutex_threading_ready_init_func, LK_INIT_LEVEL_THREADING);
+
+#endif
 
 /**
  * @brief  Initialize a mutex_t
@@ -86,6 +101,7 @@ status_t mutex_acquire_timeout(mutex_t *m, lk_time_t timeout)
         panic("mutex_acquire_timeout: thread %p (%s) tried to acquire mutex %p it already owns.\n",
               get_current_thread(), get_current_thread()->name, m);
 #endif
+    DEBUG_ASSERT(!mutex_threading_ready || !timeout || !arch_ints_disabled());
 
     THREAD_LOCK(state);
 
diff --git a/lib/libc/rand/rand.c b/lib/libc/rand.c
similarity index 96%
rename from lib/libc/rand/rand.c
rename to lib/libc/rand.c
index 74ab2c97..5bc5d36c 100644
--- a/lib/libc/rand/rand.c
+++ b/lib/libc/rand.c
@@ -23,7 +23,7 @@
 #include <rand.h>
 #include <sys/types.h>
 
-static unsigned int randseed = KERNEL_LIBC_RANDSEED;
+static unsigned int randseed = 12345;
 
 void srand(unsigned int seed)
 {
diff --git a/lib/libc/rand/rules.mk b/lib/libc/rand/rules.mk
deleted file mode 100644
index cf051d80..00000000
--- a/lib/libc/rand/rules.mk
+++ /dev/null
@@ -1,22 +0,0 @@
-
-# compile libc rand as a separate module as it is build
-# every time due to randomly changing module define
-
-LOCAL_DIR := $(GET_LOCAL_DIR)
-
-MODULE := $(LOCAL_DIR)
-
-# Generate a random 32-bit seed for the RNG
-XXD := $(PATH_TOOLS_BINDIR)/xxd
-KERNEL_LIBC_RANDSEED_HEX := $(shell $(XXD) -l4 -g0 -p /dev/urandom)
-KERNEL_LIBC_RANDSEED := 0x$(KERNEL_LIBC_RANDSEED_HEX)U
-
-MODULE_DEFINES += \
-	KERNEL_LIBC_RANDSEED=$(KERNEL_LIBC_RANDSEED) \
-
-$(info KERNEL_LIBC_RANDSEED = $(KERNEL_LIBC_RANDSEED))
-
-MODULE_SRCS += \
-	$(LOCAL_DIR)/rand.c \
-
-include make/module.mk
diff --git a/lib/libc/rules.mk b/lib/libc/rules.mk
index 9b0b5f9e..81d9ccfe 100644
--- a/lib/libc/rules.mk
+++ b/lib/libc/rules.mk
@@ -4,7 +4,6 @@ MODULE := $(LOCAL_DIR)
 
 MODULE_DEPS := \
 	lib/io \
-	lib/libc/rand
 
 ifndef WITH_CUSTOM_MALLOC
 MODULE_DEPS += lib/heap
@@ -18,6 +17,7 @@ MODULE_SRCS += \
 	$(LOCAL_DIR)/ctype.c \
 	$(LOCAL_DIR)/errno.c \
 	$(LOCAL_DIR)/printf.c \
+	$(LOCAL_DIR)/rand.c \
 	$(LOCAL_DIR)/strtol.c \
 	$(LOCAL_DIR)/strtoll.c \
 	$(LOCAL_DIR)/stdio.c \
diff --git a/lib/libc/string/memcmp.c b/lib/libc/string/memcmp.c
index c9e6a64e..60380257 100644
--- a/lib/libc/string/memcmp.c
+++ b/lib/libc/string/memcmp.c
@@ -46,4 +46,8 @@ memcmp(const void *cs, const void *ct, size_t count)
  * sometimes generates bcmp calls, and we do not have a specialized bcmp
  * implementation.
  */
-int bcmp(const void *cs, const void *ct, size_t count) __WEAK_ALIAS("memcmp");
+int __WEAK bcmp(const void *cs, const void *ct, size_t count) {
+    return memcmp(cs, ct, count);
+}
+
+
diff --git a/lib/rust_support/log.rs b/lib/rust_support/log.rs
index 74d21ea7..1875ecf8 100644
--- a/lib/rust_support/log.rs
+++ b/lib/rust_support/log.rs
@@ -23,16 +23,20 @@
 
 // TODO: replace with `trusty-log` crate once it is `no_std`-compatible
 
-use alloc::ffi::CString;
-use alloc::format;
 use core::ffi::c_uint;
+use core::ffi::c_ulong;
+use core::ffi::c_void;
+use core::fmt;
+use core::fmt::Result;
+use core::fmt::Write;
+use core::format_args;
 use log::{LevelFilter, Log, Metadata, Record};
 
 use crate::init::lk_init_level;
 use crate::LK_INIT_HOOK;
 
 use crate::sys::fflush;
-use crate::sys::fputs;
+use crate::sys::fwrite;
 use crate::sys::lk_stderr;
 use crate::sys::LK_LOGLEVEL_RUST;
 
@@ -40,6 +44,35 @@ static TRUSTY_LOGGER: TrustyKernelLogger = TrustyKernelLogger;
 
 pub struct TrustyKernelLogger;
 
+// The core::fmt::Write methods used to print formatted logs take a `&mut Self` so if
+// TrustyKernelLogger were to implement them they could not be called from Log::log. Instead we
+// define a private, stateless type to implement Write.
+struct TrustyKernelWriter;
+
+impl Write for TrustyKernelWriter {
+    fn write_str(&mut self, msg: &str) -> Result {
+        let msg = msg.as_bytes();
+        // rust formatting should not insert nulls into msg, but avoid printing messages with
+        // internal null bytes in case the fwrite implementation assumes that the pointer contains
+        // no internal null bytes.
+        if msg.contains(&0) {
+            return Err(fmt::Error);
+        }
+        // Safety: The pointer returned by `msg.as_ptr()` is valid for the duration of the `fwrite`
+        // call and it doesn't need to be null-terminated since we're passing the message length as
+        // the `count` argument to `fwrite`.
+        unsafe {
+            fwrite(
+                msg.as_ptr().cast::<c_void>(),
+                size_of::<u8>() as c_ulong,
+                msg.len().try_into().unwrap(),
+                lk_stderr(),
+            );
+        }
+        Ok(())
+    }
+}
+
 impl Log for TrustyKernelLogger {
     fn enabled(&self, _metadata: &Metadata) -> bool {
         true
@@ -47,12 +80,10 @@ impl Log for TrustyKernelLogger {
 
     fn log(&self, record: &Record) {
         if self.enabled(record.metadata()) {
-            let cstr = CString::new(format!("{} - {}\n", record.level(), record.args())).unwrap();
-            // Safety:
-            // The pointer returned by `cstr.as_ptr()` is valid because the lifetime of the
-            // `CString` encompasses the lifetime of the unsafe block.
-            // `lk_stderr()` returns a FILE pointer that is valid or null.
-            unsafe { fputs(cstr.as_ptr(), lk_stderr()) };
+            let mut writer = TrustyKernelWriter;
+            // Use format_args! instead of format! and print with a method from the Write trait to
+            // avoid heap allocations.
+            writer.write_fmt(format_args!("{} - {}\n", record.level(), record.args())).ok();
         }
     }
 
diff --git a/lib/rust_support/rules.mk b/lib/rust_support/rules.mk
index fd23e763..50a8e9cc 100644
--- a/lib/rust_support/rules.mk
+++ b/lib/rust_support/rules.mk
@@ -52,7 +52,7 @@ MODULE_BINDGEN_ALLOW_FUNCTIONS := \
 	event_signal \
 	event_wait_timeout \
 	fflush \
-	fputs \
+	fwrite \
 	handle_close \
 	handle_decref \
 	handle_set_detach_ref \
@@ -158,6 +158,7 @@ MODULE_BINDGEN_FLAGS := \
 	--with-derive-custom Error=FromPrimitive \
 	--with-derive-custom handle_waiter=Default \
 	--with-derive-custom ipc_msg_info=Default \
+	--with-derive-eq \
 
 MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
 
diff --git a/lib/rust_support/uuid.rs b/lib/rust_support/uuid.rs
index 81de2a05..8df53ca1 100644
--- a/lib/rust_support/uuid.rs
+++ b/lib/rust_support/uuid.rs
@@ -24,7 +24,7 @@
 use crate::sys::uuid_t;
 
 // TODO: split this into a separate trusty module to share bindings with userspace
-#[derive(Debug)]
+#[derive(Debug, PartialEq, Eq)]
 pub struct Uuid(pub uuid_t);
 
 impl Uuid {
```

