```diff
diff --git a/BufferAllocator.cpp b/BufferAllocator.cpp
index 0c625f6..929c648 100644
--- a/BufferAllocator.cpp
+++ b/BufferAllocator.cpp
@@ -233,13 +233,14 @@ int BufferAllocator::DmabufAlloc(const std::string& heap_name, size_t len, int f
 }
 
 int BufferAllocator::DmabufSetName(unsigned int dmabuf_fd, const std::string& name) {
-    /* dma_buf_set_name truncates instead of returning an error */
-    if (name.length() > DMA_BUF_NAME_LEN) {
-        errno = ENAMETOOLONG;
-        return -1;
-    }
-
-    return TEMP_FAILURE_RETRY(ioctl(dmabuf_fd, DMA_BUF_SET_NAME_B, name.c_str()));
+    /*
+     * Truncate the name here to avoid failure if the length exceeds the limit.
+     * length() does not count the '\0' character at the end of the string,
+     * but the kernel does, ioctl() would also fail if len == DMA_BUF_NAME_LEN.
+     * So we limit the maximum length of the name to 'DMA_BUF_NAME_LEN - 1'.
+     */
+    const std::string truncated_name = name.substr(0, DMA_BUF_NAME_LEN - 1);
+    return TEMP_FAILURE_RETRY(ioctl(dmabuf_fd, DMA_BUF_SET_NAME_B, truncated_name.c_str()));
 }
 
 int BufferAllocator::IonAlloc(const std::string& heap_name, size_t len,
```

