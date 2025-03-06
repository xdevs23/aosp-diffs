```diff
diff --git a/components/DecodeComponent.cpp b/components/DecodeComponent.cpp
index c88fa03..00880d7 100644
--- a/components/DecodeComponent.cpp
+++ b/components/DecodeComponent.cpp
@@ -243,6 +243,10 @@ void DecodeComponent::stopTask() {
 
 c2_status_t DecodeComponent::reset() {
     ALOGV("%s()", __func__);
+    auto currentState = mComponentState.load();
+
+    if (currentState == ComponentState::STOPPED)
+        return C2_OK;
 
     return stop();
 }
diff --git a/components/EncodeComponent.cpp b/components/EncodeComponent.cpp
index fc542fa..65de283 100644
--- a/components/EncodeComponent.cpp
+++ b/components/EncodeComponent.cpp
@@ -437,6 +437,14 @@ void EncodeComponent::queueTask(std::unique_ptr<C2Work> work) {
     ALOGV("Queuing next encode (index: %" PRIu64 ", timestamp: %" PRId64 ", EOS: %d)", index,
           timestamp, endOfStream);
 
+    // If input buffer list is not empty, it means we have some input to process
+    // on. However, input could be a null buffer. In such case, clear the buffer
+    // list before making call to process().
+    if (!work->input.buffers.empty() && !work->input.buffers[0]) {
+        ALOGD("Encountered null input buffer. Clearing the input buffer");
+        work->input.buffers.clear();
+    }
+
     // The codec 2.0 framework might queue an empty CSD request, but this is currently not
     // supported. We will return the CSD with the first encoded buffer work.
     if (work->input.buffers.empty() && !endOfStream) {
```

