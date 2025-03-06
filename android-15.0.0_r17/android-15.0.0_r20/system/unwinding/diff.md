```diff
diff --git a/libunwindstack/ThreadEntry.cpp b/libunwindstack/ThreadEntry.cpp
index 0e62f09..e2463ef 100644
--- a/libunwindstack/ThreadEntry.cpp
+++ b/libunwindstack/ThreadEntry.cpp
@@ -85,13 +85,17 @@ const char* ThreadEntry::GetWaitTypeName(WaitType type) {
   }
 }
 
-bool ThreadEntry::Wait(WaitType type) {
+bool ThreadEntry::Wait(WaitType type, pid_t tid) {
   static const std::chrono::duration wait_time(std::chrono::seconds(10));
   std::unique_lock<std::mutex> lock(wait_mutex_);
   if (wait_cond_.wait_for(lock, wait_time, [this, type] { return wait_value_ == type; })) {
     return true;
   } else {
-    Log::AsyncSafe("Timeout waiting for %s", GetWaitTypeName(type));
+    if (tid == 0) {
+      Log::AsyncSafe("In thread being unwound: Timeout waiting for %s", GetWaitTypeName(type));
+    } else {
+      Log::AsyncSafe("Unwinding thread %d: Timeout waiting for %s", tid, GetWaitTypeName(type));
+    }
     return false;
   }
 }
diff --git a/libunwindstack/ThreadEntry.h b/libunwindstack/ThreadEntry.h
index 32501e2..550efe1 100644
--- a/libunwindstack/ThreadEntry.h
+++ b/libunwindstack/ThreadEntry.h
@@ -40,7 +40,7 @@ class ThreadEntry {
 
   void Wake();
 
-  bool Wait(WaitType type);
+  bool Wait(WaitType type, pid_t tid);
 
   void CopyUcontextFromSigcontext(void* sigcontext);
 
diff --git a/libunwindstack/ThreadUnwinder.cpp b/libunwindstack/ThreadUnwinder.cpp
index 71835db..a02b665 100644
--- a/libunwindstack/ThreadUnwinder.cpp
+++ b/libunwindstack/ThreadUnwinder.cpp
@@ -57,9 +57,9 @@ static void SignalHandler(int, siginfo_t*, void* sigcontext) {
   entry->Wake();
   // Pause the thread until the unwind is complete. This avoids having
   // the thread run ahead causing problems.
-  // The number indicates that we are waiting for the second Wake() call
-  // overall which is made by the thread requesting an unwind.
-  if (entry->Wait(WAIT_FOR_UNWIND_TO_COMPLETE)) {
+  // We are waiting for the second Wake() call overall which is made by the
+  // thread requesting the unwind.
+  if (entry->Wait(WAIT_FOR_UNWIND_TO_COMPLETE, 0)) {
     // Do not remove the entry here because that can result in a deadlock
     // if the code cannot properly send a signal to the thread under test.
     entry->Wake();
@@ -116,7 +116,7 @@ ThreadEntry* ThreadUnwinder::SendSignalToThread(int signal, pid_t tid) {
 
   // Wait for the thread to get the ucontext. The number indicates
   // that we are waiting for the first Wake() call made by the thread.
-  bool wait_completed = entry->Wait(WAIT_FOR_UCONTEXT);
+  bool wait_completed = entry->Wait(WAIT_FOR_UCONTEXT, tid);
   if (wait_completed) {
     return entry;
   }
@@ -176,7 +176,7 @@ void ThreadUnwinder::UnwindWithSignal(int signal, pid_t tid, std::unique_ptr<Reg
 
   // Wait for the thread to indicate it is done with the ThreadEntry.
   // If this fails, the Wait command will log an error message.
-  entry->Wait(WAIT_FOR_THREAD_TO_RESTART);
+  entry->Wait(WAIT_FOR_THREAD_TO_RESTART, tid);
 
   ThreadEntry::Remove(entry);
 }
```

