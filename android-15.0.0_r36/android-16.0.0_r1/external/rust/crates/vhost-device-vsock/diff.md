```diff
diff --git a/src/vhu_vsock.rs b/src/vhu_vsock.rs
index 34ef99a..207a9b5 100644
--- a/src/vhu_vsock.rs
+++ b/src/vhu_vsock.rs
@@ -256,7 +256,9 @@ impl VhostUserVsockBackend {
     }
 }
 
-impl VhostUserBackend<VringRwLock, ()> for VhostUserVsockBackend {
+impl VhostUserBackend for VhostUserVsockBackend {
+    type Vring = VringRwLock;
+    type Bitmap = ();
     fn num_queues(&self) -> usize {
         NUM_QUEUES
     }
@@ -295,7 +297,7 @@ impl VhostUserBackend<VringRwLock, ()> for VhostUserVsockBackend {
         evset: EventSet,
         vrings: &[VringRwLock],
         thread_id: usize,
-    ) -> IoResult<bool> {
+    ) -> IoResult<()> {
         let vring_rx = &vrings[0];
         let vring_tx = &vrings[1];
 
@@ -328,7 +330,7 @@ impl VhostUserBackend<VringRwLock, ()> for VhostUserVsockBackend {
             SIBLING_VM_EVENT => {
                 let _ = thread.sibling_event_fd.read();
                 thread.process_raw_pkts(vring_rx, evt_idx)?;
-                return Ok(false);
+                return Ok(());
             }
             _ => {
                 return Err(Error::HandleUnknownEvent.into());
@@ -339,7 +341,7 @@ impl VhostUserBackend<VringRwLock, ()> for VhostUserVsockBackend {
             thread.process_rx(vring_rx, evt_idx)?;
         }
 
-        Ok(false)
+        Ok(())
     }
 
     fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
diff --git a/src/vhu_vsock_thread.rs b/src/vhu_vsock_thread.rs
index 850ad0c..5cce0a8 100644
--- a/src/vhu_vsock_thread.rs
+++ b/src/vhu_vsock_thread.rs
@@ -242,7 +242,7 @@ impl VhostUserVsockThread {
     /// Register our listeners in the VringEpollHandler
     pub fn register_listeners(
         &mut self,
-        epoll_handler: Arc<VringEpollHandler<ArcVhostBknd, VringRwLock, ()>>,
+        epoll_handler: Arc<VringEpollHandler<ArcVhostBknd>>,
     ) {
         epoll_handler
             .register_listener(self.get_epoll_fd(), EventSet::IN, u64::from(BACKEND_EVENT))
```

