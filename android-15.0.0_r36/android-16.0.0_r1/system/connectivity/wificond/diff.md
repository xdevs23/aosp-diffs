```diff
diff --git a/OWNERS b/OWNERS
index bed29cb..bc59c59 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,2 @@
-etancohen@google.com
 arabawy@google.com
 kumachang@google.com
diff --git a/fuzzers/wificond_service_fuzzer.cpp b/fuzzers/wificond_service_fuzzer.cpp
index 503568f..1ad0070 100644
--- a/fuzzers/wificond_service_fuzzer.cpp
+++ b/fuzzers/wificond_service_fuzzer.cpp
@@ -37,7 +37,8 @@ using namespace android;
 void fuzzOnBinderReadReady(int /*fd*/) {}
 
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
-
+    // TODO(b/183141167): need to rewrite 'dump' to avoid SIGPIPE.
+    signal(SIGPIPE, SIG_IGN);
     FuzzedDataProvider provider(data, size);
     auto randomFds = getRandomFds(&provider);
 
diff --git a/looper_backed_event_loop.cpp b/looper_backed_event_loop.cpp
index e97d1d9..fbe5749 100644
--- a/looper_backed_event_loop.cpp
+++ b/looper_backed_event_loop.cpp
@@ -69,7 +69,7 @@ namespace wificond {
 
 
 LooperBackedEventLoop::LooperBackedEventLoop()
-    : should_continue_(true) {
+    : polling_is_active_(true) {
   looper_ = android::Looper::prepare(Looper::PREPARE_ALLOW_NON_CALLBACKS);
 }
 
@@ -119,7 +119,7 @@ bool LooperBackedEventLoop::StopWatchFileDescriptor(int fd) {
 }
 
 void LooperBackedEventLoop::Poll() {
-  while (should_continue_) {
+  while (polling_is_active_) {
     looper_->pollOnce(-1);
   }
 }
@@ -129,7 +129,11 @@ void LooperBackedEventLoop::PollForOne(int timeout_millis) {
 }
 
 void LooperBackedEventLoop::TriggerExit() {
-  PostTask([this](){ should_continue_ = false; });
+  // Avoid reposting the exit task if polling has already been disabled.
+  // Otherwise, the task may still be in the queue after the poll loop has exited.
+  if (polling_is_active_) {
+    PostTask([this](){ polling_is_active_ = false; });
+  }
 }
 
 }  // namespace wificond
diff --git a/looper_backed_event_loop.h b/looper_backed_event_loop.h
index 02729d1..37c3c29 100644
--- a/looper_backed_event_loop.h
+++ b/looper_backed_event_loop.h
@@ -60,7 +60,7 @@ class LooperBackedEventLoop: public EventLoop {
 
  private:
   sp<android::Looper> looper_;
-  bool should_continue_;
+  bool polling_is_active_;
 
   DISALLOW_COPY_AND_ASSIGN(LooperBackedEventLoop);
 };
```

