```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 51d3f04..c169b0f 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -6,6 +6,7 @@
 ### Changed
 
 ### Fixed
+- [#800](https://github.com/rust-vmm/vhost-device/pull/800) Disable EPOLLOUT if triggered while txbuf is empty
 
 ### Deprecated
 
diff --git a/patches/fix_copy.diff b/patches/fix_copy.diff
new file mode 100644
index 0000000..a3cf5cb
--- /dev/null
+++ b/patches/fix_copy.diff
@@ -0,0 +1,26 @@
+diff --git a/src/txbuf.rs b/src/txbuf.rs
+index ef718d7..b18c80f 100644
+--- a/src/txbuf.rs
++++ b/src/txbuf.rs
+@@ -2,7 +2,7 @@
+
+ use std::{io::Write, num::Wrapping};
+
+-use vm_memory::{bitmap::BitmapSlice, VolatileSlice};
++use vm_memory::{bitmap::BitmapSlice, VolatileMemory, VolatileSlice};
+
+ use crate::vhu_vsock::{Error, Result};
+
+@@ -55,7 +55,11 @@ impl LocalTxBuf {
+         // Check if there is more data to be wrapped around
+         if len < data_buf.len() {
+             let remain_txbuf = &mut self.buf[..(data_buf.len() - len)];
+-            data_buf.copy_to(remain_txbuf);
++            // SAFETY ok to unwrap because len < data_buf.len()
++            data_buf
++                .get_slice(len, data_buf.len() - len)
++                .unwrap()
++                .copy_to(remain_txbuf);
+         }
+
+         // Increment tail by the amount of data that has been added to the buffer
diff --git a/src/txbuf.rs b/src/txbuf.rs
index ef718d7..0e6dd88 100644
--- a/src/txbuf.rs
+++ b/src/txbuf.rs
@@ -2,7 +2,7 @@
 
 use std::{io::Write, num::Wrapping};
 
-use vm_memory::{bitmap::BitmapSlice, VolatileSlice};
+use vm_memory::{bitmap::BitmapSlice, VolatileMemory, VolatileSlice};
 
 use crate::vhu_vsock::{Error, Result};
 
@@ -55,7 +55,11 @@ impl LocalTxBuf {
         // Check if there is more data to be wrapped around
         if len < data_buf.len() {
             let remain_txbuf = &mut self.buf[..(data_buf.len() - len)];
-            data_buf.copy_to(remain_txbuf);
+            // SAFETY ok to unwrap because len < data_buf.len()
+            data_buf
+                .get_slice(len, data_buf.len() - len)
+                .unwrap()
+                .copy_to(remain_txbuf);
         }
 
         // Increment tail by the amount of data that has been added to the buffer
diff --git a/src/vhu_vsock_thread.rs b/src/vhu_vsock_thread.rs
index 5cce0a8..24dd1cb 100644
--- a/src/vhu_vsock_thread.rs
+++ b/src/vhu_vsock_thread.rs
@@ -17,7 +17,7 @@ use std::{
     thread,
 };
 
-use log::warn;
+use log::{error, warn};
 use vhost_user_backend::{VringEpollHandler, VringRwLock, VringT};
 use virtio_queue::QueueOwnedT;
 use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
@@ -377,6 +377,9 @@ impl VhostUserVsockThread {
                 .unwrap();
             } else {
                 // Previously connected connection
+
+                // Get epoll fd before getting conn as that takes self mut ref
+                let epoll_fd = self.get_epoll_fd();
                 let key = self.thread_backend.listener_map.get(&fd).unwrap();
                 let conn = self.thread_backend.conn_map.get_mut(key).unwrap();
 
@@ -387,6 +390,12 @@ impl VhostUserVsockThread {
                             if cnt > 0 {
                                 conn.fwd_cnt += Wrapping(cnt as u32);
                                 conn.rx_queue.enqueue(RxOps::CreditUpdate);
+                            } else {
+                                // If no remaining data to flush, try to disable EPOLLOUT
+                                if Self::epoll_modify(epoll_fd, fd, epoll::Events::EPOLLIN).is_err()
+                                {
+                                    error!("Failed to disable EPOLLOUT");
+                                }
                             }
                             self.thread_backend
                                 .backend_rxq
diff --git a/src/vsock_conn.rs b/src/vsock_conn.rs
index 0a766df..868200c 100644
--- a/src/vsock_conn.rs
+++ b/src/vsock_conn.rs
@@ -340,6 +340,16 @@ impl<S: AsRawFd + Read + Write> VsockConnection<S> {
         }
 
         if written_count != buf.len() {
+            // Try to re-enable EPOLLOUT in case it is disabled when txbuf is empty.
+            if VhostUserVsockThread::epoll_modify(
+                self.epoll_fd,
+                self.stream.as_raw_fd(),
+                epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
+            )
+            .is_err()
+            {
+                error!("Failed to re-enable EPOLLOUT");
+            }
             return self.tx_buf.push(&buf.offset(written_count).unwrap());
         }
 
```

