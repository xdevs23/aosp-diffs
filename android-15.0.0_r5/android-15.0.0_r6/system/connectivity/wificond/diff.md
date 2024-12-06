```diff
diff --git a/net/netlink_manager.cpp b/net/netlink_manager.cpp
index 95d8a46..ecd8007 100644
--- a/net/netlink_manager.cpp
+++ b/net/netlink_manager.cpp
@@ -109,16 +109,22 @@ void NetlinkManager::ReceivePacketAndRunHandler(int fd) {
   }
   // There might be multiple message in one datagram payload.
   uint8_t* ptr = ReceiveBuffer;
-  while (ptr < ReceiveBuffer + len) {
+  uint8_t* rcv_buf_end = ReceiveBuffer + len;
+  while (ptr < rcv_buf_end) {
     // peek at the header.
-    if (ptr + sizeof(nlmsghdr) > ReceiveBuffer + len) {
-      LOG(ERROR) << "payload is broken.";
+    if (ptr + sizeof(nlmsghdr) > rcv_buf_end) {
+      LOG(ERROR) << "Remaining buffer is too small to contain a message header";
       return;
     }
     const nlmsghdr* nl_header = reinterpret_cast<const nlmsghdr*>(ptr);
+    int msg_len = nl_header->nlmsg_len;
+    if (ptr + msg_len > rcv_buf_end) {
+      LOG(ERROR) << "Remaining buffer is smaller than the expected message size " << msg_len;
+      return;
+    }
     unique_ptr<NL80211Packet> packet(
-        new NL80211Packet(vector<uint8_t>(ptr, ptr + nl_header->nlmsg_len)));
-    ptr += nl_header->nlmsg_len;
+        new NL80211Packet(vector<uint8_t>(ptr, ptr + msg_len)));
+    ptr += msg_len;
     if (!packet->IsValid()) {
       LOG(ERROR) << "Receive invalid packet";
       return;
```

