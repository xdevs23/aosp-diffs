```diff
diff --git a/resources/heyg-us-female-help-me-write-a-thank-you-note.wav b/resources/heyg-us-female-help-me-write-a-thank-you-note.wav
new file mode 100644
index 0000000..2d30776
Binary files /dev/null and b/resources/heyg-us-female-help-me-write-a-thank-you-note.wav differ
diff --git a/resources/heyg-us-female-whats-the-weather-tomorrow.wav b/resources/heyg-us-female-whats-the-weather-tomorrow.wav
new file mode 100644
index 0000000..f2f11c5
Binary files /dev/null and b/resources/heyg-us-female-whats-the-weather-tomorrow.wav differ
diff --git a/resources/heyg-us-female.wav b/resources/heyg-us-female.wav
index 25574f3..7db2a0a 100644
Binary files a/resources/heyg-us-female.wav and b/resources/heyg-us-female.wav differ
diff --git a/resources/okg-us-female-explain-how-a-rainbow-is-formed.wav b/resources/okg-us-female-explain-how-a-rainbow-is-formed.wav
new file mode 100644
index 0000000..99b7b90
Binary files /dev/null and b/resources/okg-us-female-explain-how-a-rainbow-is-formed.wav differ
diff --git a/resources/okg-us-female-set-a-timer-for-5-minutes.wav b/resources/okg-us-female-set-a-timer-for-5-minutes.wav
new file mode 100644
index 0000000..6d69b79
Binary files /dev/null and b/resources/okg-us-female-set-a-timer-for-5-minutes.wav differ
diff --git a/resources/okg-us-female.wav b/resources/okg-us-female.wav
index 7683e0e..dc42a9f 100644
Binary files a/resources/okg-us-female.wav and b/resources/okg-us-female.wav differ
diff --git a/resources/stress_test.enroll_with_queries.ascii_proto b/resources/stress_test.enroll_with_queries.ascii_proto
index 7ba1c1e..968548f 100644
--- a/resources/stress_test.enroll_with_queries.ascii_proto
+++ b/resources/stress_test.enroll_with_queries.ascii_proto
@@ -1,29 +1,29 @@
 description: "Simple script that plays Voice Match Phrases to enroll"
 
-# First phrase: Ok Google, what’s the weather tomorrow?
+# First phrase: Hey Google, help me write a thank you note.
 step {
-  audio_file : "okg-us-female-whats-the-weather-tomorrow.wav"
+  audio_file : "heyg-us-female-help-me-write-a-thank-you-note.wav"
   audio_file_sample_rate : 24000
   delay_after : 10
 }
 
-# Second phrase: Ok Google, remind me to water my plants every Monday.
+# Second phrase: Hey Google, what's the weather tomorrow?
 step {
-  audio_file : "okg-us-female-remind-me-to-water-my-plants-every-monday.wav"
+  audio_file : "heyg-us-female-whats-the-weather-tomorrow.wav"
   audio_file_sample_rate : 24000
   delay_after : 10
 }
 
-# Third phrase: Hey Google, make a call.
+# Third phrase: Ok Google, explain how a rainbow is formed.
 step {
-  audio_file : "heyg-us-female-make-a-call.wav"
+  audio_file : "okg-us-female-explain-how-a-rainbow-is-formed.wav"
   audio_file_sample_rate : 24000
   delay_after : 10
 }
 
-# Fourth phrase: Hey Google, set a timer for 5 minutes.
+# Fourth phrase: Ok Google, set a timer for 5 minutes.
 step {
-  audio_file : "heyg-us-female-set-a-timer-for-5-minutes.wav"
+  audio_file : "okg-us-female-set-a-timer-for-5-minutes.wav"
   audio_file_sample_rate : 24000
   delay_after : 10
 }
```

