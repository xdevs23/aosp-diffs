```diff
diff --git a/ql-tipc/rpmb_proxy.c b/ql-tipc/rpmb_proxy.c
index 9e5800a..dc7b593 100644
--- a/ql-tipc/rpmb_proxy.c
+++ b/ql-tipc/rpmb_proxy.c
@@ -214,6 +214,8 @@ static int proxy_handle_req(struct trusty_ipc_chan* chan,
         break;
 
     default:
+        trusty_error("%s: encountered unknown storage_cmd %zu\n", __func__,
+                     msg->cmd);
         msg->result = STORAGE_ERR_UNIMPLEMENTED;
         rc = proxy_send_response(chan, msg, NULL, 0);
     }
```

