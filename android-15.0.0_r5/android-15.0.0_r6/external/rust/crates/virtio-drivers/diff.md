```diff
diff --git a/.cargo_vcs_info.json b/.cargo_vcs_info.json
index 019e142..a4de13b 100644
--- a/.cargo_vcs_info.json
+++ b/.cargo_vcs_info.json
@@ -1,6 +1,6 @@
 {
   "git": {
-    "sha1": "463096f4dadb824056ab69cc4d83a4ca26999355"
+    "sha1": "67af14b4333924f02a2c5faa23a6155815dc902e"
   },
   "path_in_vcs": ""
 }
\ No newline at end of file
diff --git a/Android.bp b/Android.bp
index 55fd36f..00cb966 100644
--- a/Android.bp
+++ b/Android.bp
@@ -26,7 +26,7 @@ rust_library_rlib {
     name: "libvirtio_drivers",
     crate_name: "virtio_drivers",
     cargo_env_compat: true,
-    cargo_pkg_version: "0.7.3",
+    cargo_pkg_version: "0.7.4",
     crate_root: "src/lib.rs",
     edition: "2018",
     features: ["alloc"],
@@ -51,7 +51,7 @@ rust_test {
     name: "virtio-drivers_test_src_lib",
     crate_name: "virtio_drivers",
     cargo_env_compat: true,
-    cargo_pkg_version: "0.7.3",
+    cargo_pkg_version: "0.7.4",
     crate_root: "src/lib.rs",
     test_suites: ["general-tests"],
     auto_gen_config: true,
diff --git a/Cargo.toml b/Cargo.toml
index 97f5fb5..33b96aa 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -12,7 +12,7 @@
 [package]
 edition = "2018"
 name = "virtio-drivers"
-version = "0.7.3"
+version = "0.7.4"
 authors = [
     "Jiajie Chen <noc@jiegec.ac.cn>",
     "Runji Wang <wangrunji0408@163.com>",
diff --git a/Cargo.toml.orig b/Cargo.toml.orig
index 21eef42..7829b56 100644
--- a/Cargo.toml.orig
+++ b/Cargo.toml.orig
@@ -1,6 +1,6 @@
 [package]
 name = "virtio-drivers"
-version = "0.7.3"
+version = "0.7.4"
 license = "MIT"
 authors = [
   "Jiajie Chen <noc@jiegec.ac.cn>",
diff --git a/METADATA b/METADATA
index 5f22ca2..0cb5da9 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 6
-    day: 12
+    month: 7
+    day: 15
   }
   homepage: "https://crates.io/crates/virtio-drivers"
   identifier {
     type: "Archive"
-    value: "https://static.crates.io/crates/virtio-drivers/virtio-drivers-0.7.3.crate"
-    version: "0.7.3"
+    value: "https://static.crates.io/crates/virtio-drivers/virtio-drivers-0.7.4.crate"
+    version: "0.7.4"
   }
 }
diff --git a/cargo2rulesmk.json b/cargo2rulesmk.json
deleted file mode 100644
index 5733757..0000000
--- a/cargo2rulesmk.json
+++ /dev/null
@@ -1,3 +0,0 @@
-{
-    "patch": "patches/rules.mk.diff"
-}
\ No newline at end of file
diff --git a/cargo_embargo.json b/cargo_embargo.json
index dc841c6..34ba893 100644
--- a/cargo_embargo.json
+++ b/cargo_embargo.json
@@ -7,11 +7,20 @@
       "force_rlib": true,
       "host_supported": false,
       "no_std": true,
-      "patch": "patches/Android.bp.patch"
+      "patch": "patches/Android.bp.patch",
+      "rulesmk_patch": "patches/rules.mk.diff"
     }
   },
   "product_available": false,
   "run_cargo": false,
   "tests": true,
-  "vendor_available": false
+  "vendor_available": false,
+  "variants": [
+    {},
+    {
+      "generate_androidbp": false,
+      "generate_rulesmk": true,
+      "tests": false
+    }
+  ]
 }
diff --git a/patches/Android.bp.patch b/patches/Android.bp.patch
index 45ae059..875b8b5 100644
--- a/patches/Android.bp.patch
+++ b/patches/Android.bp.patch
@@ -7,7 +7,7 @@ index 81021c8..916b74c 100644
      name: "libvirtio_drivers",
      crate_name: "virtio_drivers",
      cargo_env_compat: true,
-     cargo_pkg_version: "0.7.3",
+     cargo_pkg_version: "0.7.4",
      crate_root: "src/lib.rs",
      edition: "2018",
      features: ["alloc"],
@@ -29,7 +29,7 @@ index 81021c8..916b74c 100644
          "libcore.rust_sysroot",
 @@ -53,13 +53,13 @@ rust_test {
      cargo_env_compat: true,
-     cargo_pkg_version: "0.7.1",
+     cargo_pkg_version: "0.7.4",
      crate_root: "src/lib.rs",
      test_suites: ["general-tests"],
      auto_gen_config: true,
diff --git a/rules.mk b/rules.mk
index 7755d96..89ba5be 100644
--- a/rules.mk
+++ b/rules.mk
@@ -1,21 +1,24 @@
-# This file is generated by cargo2rulesmk.py --run --config cargo2rulesmk.json.
-# Do not modify this file as changes will be overridden on upgrade.
+# This file is generated by cargo_embargo.
+# Do not modify this file after the LOCAL_DIR line
+# because the changes will be overridden on upgrade.
+# Content before the first line starting with LOCAL_DIR is preserved.
 
 LOCAL_DIR := $(GET_LOCAL_DIR)
 MODULE := $(LOCAL_DIR)
 MODULE_CRATE_NAME := virtio_drivers
-MODULE_SRCS := \
-	$(LOCAL_DIR)/src/lib.rs \
-
+MODULE_RUST_CRATE_TYPES := rlib
+MODULE_SRCS := $(LOCAL_DIR)/src/lib.rs
+MODULE_ADD_IMPLICIT_DEPS := false
 MODULE_RUST_EDITION := 2018
 MODULE_RUSTFLAGS += \
-	--cfg 'feature="alloc"' \
-	--cfg 'feature="default"' \
+	--cfg 'feature="alloc"'
 
 MODULE_LIBRARY_DEPS := \
 	trusty/user/base/lib/liballoc-rust \
 	external/rust/crates/bitflags \
 	external/rust/crates/log \
 	external/rust/crates/zerocopy \
+	trusty/user/base/lib/libcompiler_builtins-rust \
+	trusty/user/base/lib/libcore-rust
 
 include make/library.mk
diff --git a/src/device/input.rs b/src/device/input.rs
index f8ee95a..ed69076 100644
--- a/src/device/input.rs
+++ b/src/device/input.rs
@@ -4,10 +4,12 @@ use super::common::Feature;
 use crate::hal::Hal;
 use crate::queue::VirtQueue;
 use crate::transport::Transport;
-use crate::volatile::{volread, volwrite, ReadOnly, WriteOnly};
-use crate::Result;
-use alloc::boxed::Box;
-use core::ptr::NonNull;
+use crate::volatile::{volread, volwrite, ReadOnly, VolatileReadable, WriteOnly};
+use crate::Error;
+use alloc::{boxed::Box, string::String};
+use core::cmp::min;
+use core::mem::size_of;
+use core::ptr::{addr_of, NonNull};
 use zerocopy::{AsBytes, FromBytes, FromZeroes};
 
 /// Virtual human interface devices such as keyboards, mice and tablets.
@@ -25,7 +27,7 @@ pub struct VirtIOInput<H: Hal, T: Transport> {
 
 impl<H: Hal, T: Transport> VirtIOInput<H, T> {
     /// Create a new VirtIO-Input driver.
-    pub fn new(mut transport: T) -> Result<Self> {
+    pub fn new(mut transport: T) -> Result<Self, Error> {
         let mut event_buf = Box::new([InputEvent::default(); QUEUE_SIZE]);
 
         let negotiated_features = transport.begin_init(SUPPORTED_FEATURES);
@@ -107,17 +109,99 @@ impl<H: Hal, T: Transport> VirtIOInput<H, T> {
         out: &mut [u8],
     ) -> u8 {
         let size;
-        let data;
         // Safe because config points to a valid MMIO region for the config space.
         unsafe {
             volwrite!(self.config, select, select as u8);
             volwrite!(self.config, subsel, subsel);
             size = volread!(self.config, size);
-            data = volread!(self.config, data);
+            let size_to_copy = min(usize::from(size), out.len());
+            for (i, out_item) in out.iter_mut().take(size_to_copy).enumerate() {
+                *out_item = addr_of!((*self.config.as_ptr()).data[i]).vread();
+            }
         }
-        out[..size as usize].copy_from_slice(&data[..size as usize]);
         size
     }
+
+    /// Queries a specific piece of information by `select` and `subsel`, allocates a sufficiently
+    /// large byte buffer for it, and returns it.
+    fn query_config_select_alloc(
+        &mut self,
+        select: InputConfigSelect,
+        subsel: u8,
+    ) -> Result<Box<[u8]>, Error> {
+        // Safe because config points to a valid MMIO region for the config space.
+        unsafe {
+            volwrite!(self.config, select, select as u8);
+            volwrite!(self.config, subsel, subsel);
+            let size = usize::from(volread!(self.config, size));
+            if size > CONFIG_DATA_MAX_LENGTH {
+                return Err(Error::IoError);
+            }
+            let mut buf = u8::new_box_slice_zeroed(size);
+            for i in 0..size {
+                buf[i] = addr_of!((*self.config.as_ptr()).data[i]).vread();
+            }
+            Ok(buf)
+        }
+    }
+
+    /// Queries a specific piece of information by `select` and `subsel` into a newly-allocated
+    /// buffer, and tries to convert it to a string.
+    ///
+    /// Returns an error if it is not valid UTF-8.
+    fn query_config_string(
+        &mut self,
+        select: InputConfigSelect,
+        subsel: u8,
+    ) -> Result<String, Error> {
+        Ok(String::from_utf8(
+            self.query_config_select_alloc(select, subsel)?.into(),
+        )?)
+    }
+
+    /// Queries and returns the name of the device, or an error if it is not valid UTF-8.
+    pub fn name(&mut self) -> Result<String, Error> {
+        self.query_config_string(InputConfigSelect::IdName, 0)
+    }
+
+    /// Queries and returns the serial number of the device, or an error if it is not valid UTF-8.
+    pub fn serial_number(&mut self) -> Result<String, Error> {
+        self.query_config_string(InputConfigSelect::IdSerial, 0)
+    }
+
+    /// Queries and returns the ID information of the device.
+    pub fn ids(&mut self) -> Result<DevIDs, Error> {
+        let mut ids = DevIDs::default();
+        let size = self.query_config_select(InputConfigSelect::IdDevids, 0, ids.as_bytes_mut());
+        if usize::from(size) == size_of::<DevIDs>() {
+            Ok(ids)
+        } else {
+            Err(Error::IoError)
+        }
+    }
+
+    /// Queries and returns the input properties of the device.
+    pub fn prop_bits(&mut self) -> Result<Box<[u8]>, Error> {
+        self.query_config_select_alloc(InputConfigSelect::PropBits, 0)
+    }
+
+    /// Queries and returns a bitmap of supported event codes for the given event type.
+    ///
+    /// If the event type is not supported an empty slice will be returned.
+    pub fn ev_bits(&mut self, event_type: u8) -> Result<Box<[u8]>, Error> {
+        self.query_config_select_alloc(InputConfigSelect::EvBits, event_type)
+    }
+
+    /// Queries and returns information about the given axis of the device.
+    pub fn abs_info(&mut self, axis: u8) -> Result<AbsInfo, Error> {
+        let mut info = AbsInfo::default();
+        let size = self.query_config_select(InputConfigSelect::AbsInfo, axis, info.as_bytes_mut());
+        if usize::from(size) == size_of::<AbsInfo>() {
+            Ok(info)
+        } else {
+            Err(Error::IoError)
+        }
+    }
 }
 
 // SAFETY: The config space can be accessed from any thread.
@@ -141,6 +225,8 @@ impl<H: Hal, T: Transport> Drop for VirtIOInput<H, T> {
     }
 }
 
+const CONFIG_DATA_MAX_LENGTH: usize = 128;
+
 /// Select value used for [`VirtIOInput::query_config_select()`].
 #[repr(u8)]
 #[derive(Debug, Clone, Copy)]
@@ -171,27 +257,38 @@ struct Config {
     select: WriteOnly<u8>,
     subsel: WriteOnly<u8>,
     size: ReadOnly<u8>,
-    _reversed: [ReadOnly<u8>; 5],
-    data: ReadOnly<[u8; 128]>,
+    _reserved: [ReadOnly<u8>; 5],
+    data: [ReadOnly<u8>; CONFIG_DATA_MAX_LENGTH],
 }
 
+/// Information about an axis of an input device, typically a joystick.
 #[repr(C)]
-#[derive(Debug)]
-struct AbsInfo {
-    min: u32,
-    max: u32,
-    fuzz: u32,
-    flat: u32,
-    res: u32,
+#[derive(AsBytes, Clone, Debug, Default, Eq, PartialEq, FromBytes, FromZeroes)]
+pub struct AbsInfo {
+    /// The minimum value for the axis.
+    pub min: u32,
+    /// The maximum value for the axis.
+    pub max: u32,
+    /// The fuzz value used to filter noise from the event stream.
+    pub fuzz: u32,
+    /// The size of the dead zone; values less than this will be reported as 0.
+    pub flat: u32,
+    /// The resolution for values reported for the axis.
+    pub res: u32,
 }
 
+/// The identifiers of a VirtIO input device.
 #[repr(C)]
-#[derive(Debug)]
-struct DevIDs {
-    bustype: u16,
-    vendor: u16,
-    product: u16,
-    version: u16,
+#[derive(AsBytes, Clone, Debug, Default, Eq, PartialEq, FromBytes, FromZeroes)]
+pub struct DevIDs {
+    /// The bustype identifier.
+    pub bustype: u16,
+    /// The vendor identifier.
+    pub vendor: u16,
+    /// The product identifier.
+    pub product: u16,
+    /// The version identifier.
+    pub version: u16,
 }
 
 /// Both queues use the same `virtio_input_event` struct. `type`, `code` and `value`
@@ -213,3 +310,92 @@ const SUPPORTED_FEATURES: Feature = Feature::RING_EVENT_IDX.union(Feature::RING_
 
 // a parameter that can change
 const QUEUE_SIZE: usize = 32;
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::{
+        hal::fake::FakeHal,
+        transport::{
+            fake::{FakeTransport, QueueStatus, State},
+            DeviceType,
+        },
+    };
+    use alloc::{sync::Arc, vec};
+    use core::convert::TryInto;
+    use std::sync::Mutex;
+
+    #[test]
+    fn config() {
+        const DEFAULT_DATA: ReadOnly<u8> = ReadOnly::new(0);
+        let mut config_space = Config {
+            select: WriteOnly::default(),
+            subsel: WriteOnly::default(),
+            size: ReadOnly::new(0),
+            _reserved: Default::default(),
+            data: [DEFAULT_DATA; 128],
+        };
+        let state = Arc::new(Mutex::new(State {
+            queues: vec![QueueStatus::default(), QueueStatus::default()],
+            ..Default::default()
+        }));
+        let transport = FakeTransport {
+            device_type: DeviceType::Block,
+            max_queue_size: QUEUE_SIZE.try_into().unwrap(),
+            device_features: 0,
+            config_space: NonNull::from(&mut config_space),
+            state: state.clone(),
+        };
+        let mut input = VirtIOInput::<FakeHal, FakeTransport<Config>>::new(transport).unwrap();
+
+        set_data(&mut config_space, "Test input device".as_bytes());
+        assert_eq!(input.name().unwrap(), "Test input device");
+        assert_eq!(config_space.select.0, InputConfigSelect::IdName as u8);
+        assert_eq!(config_space.subsel.0, 0);
+
+        set_data(&mut config_space, "Serial number".as_bytes());
+        assert_eq!(input.serial_number().unwrap(), "Serial number");
+        assert_eq!(config_space.select.0, InputConfigSelect::IdSerial as u8);
+        assert_eq!(config_space.subsel.0, 0);
+
+        let ids = DevIDs {
+            bustype: 0x4242,
+            product: 0x0067,
+            vendor: 0x1234,
+            version: 0x4321,
+        };
+        set_data(&mut config_space, ids.as_bytes());
+        assert_eq!(input.ids().unwrap(), ids);
+        assert_eq!(config_space.select.0, InputConfigSelect::IdDevids as u8);
+        assert_eq!(config_space.subsel.0, 0);
+
+        set_data(&mut config_space, &[0x12, 0x34, 0x56]);
+        assert_eq!(input.prop_bits().unwrap().as_ref(), &[0x12, 0x34, 0x56]);
+        assert_eq!(config_space.select.0, InputConfigSelect::PropBits as u8);
+        assert_eq!(config_space.subsel.0, 0);
+
+        set_data(&mut config_space, &[0x42, 0x66]);
+        assert_eq!(input.ev_bits(3).unwrap().as_ref(), &[0x42, 0x66]);
+        assert_eq!(config_space.select.0, InputConfigSelect::EvBits as u8);
+        assert_eq!(config_space.subsel.0, 3);
+
+        let abs_info = AbsInfo {
+            min: 12,
+            max: 1234,
+            fuzz: 4,
+            flat: 10,
+            res: 2,
+        };
+        set_data(&mut config_space, abs_info.as_bytes());
+        assert_eq!(input.abs_info(5).unwrap(), abs_info);
+        assert_eq!(config_space.select.0, InputConfigSelect::AbsInfo as u8);
+        assert_eq!(config_space.subsel.0, 5);
+    }
+
+    fn set_data(config_space: &mut Config, value: &[u8]) {
+        config_space.size.0 = value.len().try_into().unwrap();
+        for (i, &byte) in value.into_iter().enumerate() {
+            config_space.data[i].0 = byte;
+        }
+    }
+}
diff --git a/src/device/net/mod.rs b/src/device/net/mod.rs
index 8375946..3b8218f 100644
--- a/src/device/net/mod.rs
+++ b/src/device/net/mod.rs
@@ -64,7 +64,8 @@ bitflags! {
         const CTRL_RX = 1 << 18;
         /// Control channel VLAN filtering.
         const CTRL_VLAN = 1 << 19;
-        ///
+        /// Device supports VIRTIO_NET_CTRL_RX_ALLUNI, VIRTIO_NET_CTRL_RX_NOMULTI,
+        /// VIRTIO_NET_CTRL_RX_NOUNI and VIRTIO_NET_CTRL_RX_NOBCAST.
         const CTRL_RX_EXTRA = 1 << 20;
         /// Driver can send gratuitous packets.
         const GUEST_ANNOUNCE = 1 << 21;
diff --git a/src/device/socket/mod.rs b/src/device/socket/mod.rs
index 3b59d65..607f739 100644
--- a/src/device/socket/mod.rs
+++ b/src/device/socket/mod.rs
@@ -17,9 +17,9 @@ mod vsock;
 #[cfg(feature = "alloc")]
 pub use connectionmanager::VsockConnectionManager;
 pub use error::SocketError;
-pub use protocol::{VsockAddr, VMADDR_CID_HOST};
+pub use protocol::{StreamShutdown, VsockAddr, VMADDR_CID_HOST};
 #[cfg(feature = "alloc")]
-pub use vsock::{DisconnectReason, VirtIOSocket, VsockEvent, VsockEventType};
+pub use vsock::{ConnectionInfo, DisconnectReason, VirtIOSocket, VsockEvent, VsockEventType};
 
 /// The size in bytes of each buffer used in the RX virtqueue. This must be bigger than
 /// `size_of::<VirtioVsockHdr>()`.
diff --git a/src/device/socket/vsock.rs b/src/device/socket/vsock.rs
index 2103753..6c5a3f2 100644
--- a/src/device/socket/vsock.rs
+++ b/src/device/socket/vsock.rs
@@ -24,9 +24,12 @@ const EVENT_QUEUE_IDX: u16 = 2;
 pub(crate) const QUEUE_SIZE: usize = 8;
 const SUPPORTED_FEATURES: Feature = Feature::RING_EVENT_IDX.union(Feature::RING_INDIRECT_DESC);
 
+/// Information about a particular vsock connection.
 #[derive(Clone, Debug, Default, PartialEq, Eq)]
 pub struct ConnectionInfo {
+    /// The address of the peer.
     pub dst: VsockAddr,
+    /// The local port number associated with the connection.
     pub src_port: u32,
     /// The last `buf_alloc` value the peer sent to us, indicating how much receive buffer space in
     /// bytes it has allocated for packet bodies.
@@ -49,6 +52,8 @@ pub struct ConnectionInfo {
 }
 
 impl ConnectionInfo {
+    /// Creates a new `ConnectionInfo` for the given peer address and local port, and default values
+    /// for everything else.
     pub fn new(destination: VsockAddr, src_port: u32) -> Self {
         Self {
             dst: destination,
@@ -228,14 +233,18 @@ pub struct VirtIOSocket<H: Hal, T: Transport, const RX_BUFFER_SIZE: usize = DEFA
 }
 
 // SAFETY: The `rx_queue_buffers` can be accessed from any thread.
-unsafe impl<H: Hal, T: Transport + Send> Send for VirtIOSocket<H, T> where
-    VirtQueue<H, QUEUE_SIZE>: Send
+unsafe impl<H: Hal, T: Transport + Send, const RX_BUFFER_SIZE: usize> Send
+    for VirtIOSocket<H, T, RX_BUFFER_SIZE>
+where
+    VirtQueue<H, QUEUE_SIZE>: Send,
 {
 }
 
 // SAFETY: A `&VirtIOSocket` only allows reading the guest CID from a field.
-unsafe impl<H: Hal, T: Transport + Sync> Sync for VirtIOSocket<H, T> where
-    VirtQueue<H, QUEUE_SIZE>: Sync
+unsafe impl<H: Hal, T: Transport + Sync, const RX_BUFFER_SIZE: usize> Sync
+    for VirtIOSocket<H, T, RX_BUFFER_SIZE>
+where
+    VirtQueue<H, QUEUE_SIZE>: Sync,
 {
 }
 
diff --git a/src/lib.rs b/src/lib.rs
index f2f2f12..2fa6ae1 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -95,6 +95,13 @@ pub enum Error {
     SocketDeviceError(device::socket::SocketError),
 }
 
+#[cfg(feature = "alloc")]
+impl From<alloc::string::FromUtf8Error> for Error {
+    fn from(_value: alloc::string::FromUtf8Error) -> Self {
+        Self::IoError
+    }
+}
+
 impl Display for Error {
     fn fmt(&self, f: &mut Formatter) -> fmt::Result {
         match self {
diff --git a/src/volatile.rs b/src/volatile.rs
index 67ebba3..caa58e2 100644
--- a/src/volatile.rs
+++ b/src/volatile.rs
@@ -1,11 +1,11 @@
 /// An MMIO register which can only be read from.
 #[derive(Default)]
 #[repr(transparent)]
-pub struct ReadOnly<T: Copy>(T);
+pub struct ReadOnly<T: Copy>(pub(crate) T);
 
 impl<T: Copy> ReadOnly<T> {
     /// Construct a new instance for testing.
-    pub fn new(value: T) -> Self {
+    pub const fn new(value: T) -> Self {
         Self(value)
     }
 }
@@ -13,7 +13,7 @@ impl<T: Copy> ReadOnly<T> {
 /// An MMIO register which can only be written to.
 #[derive(Default)]
 #[repr(transparent)]
-pub struct WriteOnly<T: Copy>(T);
+pub struct WriteOnly<T: Copy>(pub(crate) T);
 
 /// An MMIO register which may be both read and written.
 #[derive(Default)]
@@ -22,7 +22,7 @@ pub struct Volatile<T: Copy>(T);
 
 impl<T: Copy> Volatile<T> {
     /// Construct a new instance for testing.
-    pub fn new(value: T) -> Self {
+    pub const fn new(value: T) -> Self {
         Self(value)
     }
 }
```
