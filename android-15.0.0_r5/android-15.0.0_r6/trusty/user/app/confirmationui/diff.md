```diff
diff --git a/src/main.cpp b/src/main.cpp
index 7c1ddec..a69f228 100644
--- a/src/main.cpp
+++ b/src/main.cpp
@@ -170,7 +170,10 @@ static int handle_init(handle_t chan,
     return NO_ERROR;
 
 err:
-    munmap(shm_base, shm_len);
+    int rc1 = munmap(shm_base, shm_len);
+    if (rc1 != NO_ERROR) {
+        TLOGW("munmap() failed: %d\n", rc1);
+    }
     return rc;
 }
 
@@ -253,7 +256,10 @@ static int on_connect(const struct tipc_port* port,
 static void on_channel_cleanup(void* _ctx) {
     struct chan_ctx* ctx = (struct chan_ctx*)_ctx;
     /* Abort operation and free all resources. */
-    munmap(ctx->shm_base, ctx->shm_len);
+    int rc = munmap(ctx->shm_base, ctx->shm_len);
+    if (rc != NO_ERROR) {
+        TLOGW("munmap() failed: %d\n", rc);
+    }
     ctx->op->abort();
     ctx->op.reset();
     free(ctx);
```

