```diff
diff --git a/METADATA b/METADATA
index 4ab2fc3..88de40c 100644
--- a/METADATA
+++ b/METADATA
@@ -6,7 +6,7 @@ third_party {
     type: GIT
     value: "https://chromium.googlesource.com/chromiumos/platform/gestures/"
   }
-  version: "b824af1e782a4e741fbfe4b0c311de3bc161e2fc"
-  last_upgrade_date { year: 2024 month: 3 day: 13  }
+  version: "b1640b40fe62f9ae9a991e8a4674ee9e991dbc99"
+  last_upgrade_date { year: 2024 month: 8 day: 30  }
   license_type: NOTICE
 }
diff --git a/include/gestures.h b/include/gestures.h
index 3ccaa20..9b2b62e 100644
--- a/include/gestures.h
+++ b/include/gestures.h
@@ -60,12 +60,6 @@ struct HardwareProperties {
   float res_x;
   float res_y;
 
-  // Deprecated: these values are now ignored. Previously, they specified the
-  // DPI of the screen to which gestures output by the library should be
-  // scaled.
-  float screen_x_dpi;
-  float screen_y_dpi;
-
   // The minimum and maximum orientation values.
   float orientation_minimum;
   float orientation_maximum;
diff --git a/include/immediate_interpreter.h b/include/immediate_interpreter.h
index 7f2aa52..e414bf7 100644
--- a/include/immediate_interpreter.h
+++ b/include/immediate_interpreter.h
@@ -95,7 +95,7 @@ class ScrollEventBuffer {
  public:
   explicit ScrollEventBuffer(size_t size)
       : buf_(new ScrollEvent[size]), max_size_(size), size_(0), head_(0) {}
-  void Insert(float dx, float dy, float dt);
+  void Insert(float dx, float dy, stime_t timestamp, stime_t prev_timestamp);
   void Clear();
   size_t Size() const { return size_; }
   // 0 is newest, 1 is next newest, ..., size_ - 1 is oldest.
@@ -109,6 +109,7 @@ class ScrollEventBuffer {
   size_t max_size_;
   size_t size_;
   size_t head_;
+  stime_t last_scroll_timestamp_;
   DISALLOW_COPY_AND_ASSIGN(ScrollEventBuffer);
 };
 
diff --git a/src/activity_log.cc b/src/activity_log.cc
index d668f9c..fcfe751 100644
--- a/src/activity_log.cc
+++ b/src/activity_log.cc
@@ -174,8 +174,6 @@ Json::Value ActivityLog::EncodeHardwareProperties() const {
   ret[kKeyHardwarePropBottom] = Json::Value(hwprops_.bottom);
   ret[kKeyHardwarePropXResolution] = Json::Value(hwprops_.res_x);
   ret[kKeyHardwarePropYResolution] = Json::Value(hwprops_.res_y);
-  ret[kKeyHardwarePropXDpi] = Json::Value(hwprops_.screen_x_dpi);
-  ret[kKeyHardwarePropYDpi] = Json::Value(hwprops_.screen_y_dpi);
   ret[kKeyHardwarePropOrientationMinimum] =
       Json::Value(hwprops_.orientation_minimum);
   ret[kKeyHardwarePropOrientationMaximum] =
diff --git a/src/activity_log_unittest.cc b/src/activity_log_unittest.cc
index 36dd6c0..9560a7d 100644
--- a/src/activity_log_unittest.cc
+++ b/src/activity_log_unittest.cc
@@ -39,8 +39,6 @@ TEST(ActivityLogTest, SimpleTest) {
     .bottom = 6014,
     .res_x = 6015,
     .res_y = 6016,
-    .screen_x_dpi = 6017,
-    .screen_y_dpi = 6018,
     .orientation_minimum = 6019,
     .orientation_maximum = 6020,
     .max_finger_cnt = 6021,
@@ -56,8 +54,8 @@ TEST(ActivityLogTest, SimpleTest) {
   log.SetHardwareProperties(hwprops);
 
   const char* expected_strings[] = {
-    "6011", "6012", "6013", "6014", "6015", "6016",
-    "6017", "6018", "6019", "6020", "6021", "6022"
+    "6011", "6012", "6013", "6014", "6015",
+    "6016", "6019", "6020", "6021", "6022"
   };
   string hwprops_log = log.Encode();
   for (size_t i = 0; i < arraysize(expected_strings); i++)
@@ -233,8 +231,6 @@ TEST(ActivityLogTest, HardwareStatePreTest) {
     .bottom = 6014,
     .res_x = 6015,
     .res_y = 6016,
-    .screen_x_dpi = 6017,
-    .screen_y_dpi = 6018,
     .orientation_minimum = 6019,
     .orientation_maximum = 6020,
     .max_finger_cnt = 6021,
@@ -298,8 +294,6 @@ TEST(ActivityLogTest, HardwareStatePostTest) {
     .bottom = 6014,
     .res_x = 6015,
     .res_y = 6016,
-    .screen_x_dpi = 6017,
-    .screen_y_dpi = 6018,
     .orientation_minimum = 6019,
     .orientation_maximum = 6020,
     .max_finger_cnt = 6021,
diff --git a/src/activity_replay.cc b/src/activity_replay.cc
index e020be9..e62aa48 100644
--- a/src/activity_replay.cc
+++ b/src/activity_replay.cc
@@ -168,10 +168,6 @@ bool ActivityReplay::ParseHardwareProperties(const Json::Value& obj,
            props.res_x, float, true);
   PARSE_HP(obj, ActivityLog::kKeyHardwarePropYResolution, isDouble, asDouble,
            props.res_y, float, true);
-  PARSE_HP(obj, ActivityLog::kKeyHardwarePropXDpi, isDouble, asDouble,
-           props.screen_x_dpi, float, true);
-  PARSE_HP(obj, ActivityLog::kKeyHardwarePropYDpi, isDouble, asDouble,
-           props.screen_y_dpi, float, true);
   PARSE_HP(obj, ActivityLog::kKeyHardwarePropOrientationMinimum,
            isDouble, asDouble, props.orientation_minimum, float, false);
   PARSE_HP(obj, ActivityLog::kKeyHardwarePropOrientationMaximum,
@@ -238,11 +234,12 @@ bool ActivityReplay::ParseHardwareState(const Json::Value& entry) {
   }
   Json::Value fingers = entry[ActivityLog::kKeyHardwareStateFingers];
   // Sanity check
-  if (fingers.size() > 30) {
+  const size_t kMaxFingers = 30;
+  if (fingers.size() > kMaxFingers) {
     Err("Too many fingers in hardware state");
     return false;
   }
-  FingerState fs[fingers.size()];
+  FingerState fs[kMaxFingers];
   for (size_t i = 0; i < fingers.size(); ++i) {
     if (!fingers.isValidIndex(i)) {
       Err("Invalid entry at index %zu", i);
diff --git a/src/box_filter_interpreter_unittest.cc b/src/box_filter_interpreter_unittest.cc
index b2f37d7..55be355 100644
--- a/src/box_filter_interpreter_unittest.cc
+++ b/src/box_filter_interpreter_unittest.cc
@@ -22,7 +22,6 @@ using std::vector;
 static const HardwareProperties hwprops = {
   .right = 100, .bottom = 100,
   .res_x = 1, .res_y = 1,
-  .screen_x_dpi = 0, .screen_y_dpi = 0,
   .orientation_minimum = -1,
   .orientation_maximum = 2,
   .max_finger_cnt = 5, .max_touch_cnt = 5,
diff --git a/src/click_wiggle_filter_interpreter.cc b/src/click_wiggle_filter_interpreter.cc
index e4f9b10..2e63287 100644
--- a/src/click_wiggle_filter_interpreter.cc
+++ b/src/click_wiggle_filter_interpreter.cc
@@ -22,7 +22,7 @@ ClickWiggleFilterInterpreter::ClickWiggleFilterInterpreter(
       wiggle_suppress_timeout_(prop_reg, "Wiggle Timeout", 0.075),
       wiggle_button_down_timeout_(prop_reg,
                                   "Wiggle Button Down Timeout",
-                                  0.75),
+                                  0.25),
       one_finger_click_wiggle_timeout_(prop_reg,
                                        "One Finger Click Wiggle Timeout",
                                        0.2) {
diff --git a/src/click_wiggle_filter_interpreter_unittest.cc b/src/click_wiggle_filter_interpreter_unittest.cc
index a7168d9..89d1a14 100644
--- a/src/click_wiggle_filter_interpreter_unittest.cc
+++ b/src/click_wiggle_filter_interpreter_unittest.cc
@@ -59,8 +59,6 @@ TEST(ClickWiggleFilterInterpreterTest, WiggleSuppressTest) {
     .bottom = 61,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -133,8 +131,6 @@ TEST(ClickWiggleFilterInterpreterTest, OneFingerClickSuppressTest) {
     .bottom = 61,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -202,8 +198,6 @@ TEST(ClickWiggleFilterInterpreter, ThumbClickTest) {
     .bottom = 61,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -256,8 +250,6 @@ TEST(ClickWiggleFilterInterpreter, TimeBackwardsTest) {
     .bottom = 61,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -322,8 +314,6 @@ TEST(ClickWiggleFilterInterpreter, ThumbClickWiggleWithPalmTest) {
     .bottom = 68.000000,
     .res_x = 1.000000,
     .res_y = 1.000000,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 15,
diff --git a/src/finger_merge_filter_interpreter_unittest.cc b/src/finger_merge_filter_interpreter_unittest.cc
index fc804d4..4920e50 100644
--- a/src/finger_merge_filter_interpreter_unittest.cc
+++ b/src/finger_merge_filter_interpreter_unittest.cc
@@ -54,7 +54,6 @@ TEST(FingerMergeFilterInterpreterTest, SimpleTest) {
   HardwareProperties hwprops = {
     .right = 100, .bottom = 100,
     .res_x = 1, .res_y = 1,
-    .screen_x_dpi = 0, .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5, .max_touch_cnt = 5,
diff --git a/src/gestures.cc b/src/gestures.cc
index cd49c68..f5fbf5e 100644
--- a/src/gestures.cc
+++ b/src/gestures.cc
@@ -65,8 +65,6 @@ std::string HardwareProperties::String() const {
                       "%f,  // bottom edge\n"
                       "%f,  // x pixels/TP width\n"
                       "%f,  // y pixels/TP height\n"
-                      "%f,  // x screen DPI\n"
-                      "%f,  // y screen DPI\n"
                       "%f,  // orientation minimum\n"
                       "%f,  // orientation maximum\n"
                       "%u,  // max fingers\n"
@@ -77,8 +75,6 @@ std::string HardwareProperties::String() const {
                       left, top, right, bottom,
                       res_x,
                       res_y,
-                      screen_x_dpi,
-                      screen_y_dpi,
                       orientation_minimum,
                       orientation_maximum,
                       max_finger_cnt,
diff --git a/src/gestures_unittest.cc b/src/gestures_unittest.cc
index b11a339..3d56a69 100644
--- a/src/gestures_unittest.cc
+++ b/src/gestures_unittest.cc
@@ -447,8 +447,6 @@ TEST(GesturesTest, HardwarePropertiesToStringTest) {
   HardwareProperties hp = {
     .left = 1009.5, .top = 1002.4, .right = 1003.9, .bottom = 1004.5,
     .res_x = 1005.4, .res_y = 1006.9,
-    .screen_x_dpi = 1007.4,
-    .screen_y_dpi = 1008.5,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 12,
@@ -467,8 +465,6 @@ TEST(GesturesTest, HardwarePropertiesToStringTest) {
     "1004.5",
     "1005.4",
     "1006.9",
-    "1007.4",
-    "1008.5",
     "12,",
     "11,",
     "0,",
diff --git a/src/haptic_button_generator_filter_interpreter_unittest.cc b/src/haptic_button_generator_filter_interpreter_unittest.cc
index 8fef528..a57773d 100644
--- a/src/haptic_button_generator_filter_interpreter_unittest.cc
+++ b/src/haptic_button_generator_filter_interpreter_unittest.cc
@@ -49,8 +49,6 @@ TEST(HapticButtonGeneratorFilterInterpreterTest, SimpleTest) {
     .right = 100, .bottom = 100,
     .res_x = 10,
     .res_y = 10,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -138,8 +136,6 @@ TEST(HapticButtonGeneratorFilterInterpreterTest, NotHapticTest) {
     .right = 100, .bottom = 100,
     .res_x = 10,
     .res_y = 10,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -249,8 +245,6 @@ TEST(HapticButtonGeneratorFilterInterpreterTest,
     .right = 100, .bottom = 100,
     .res_x = 10,
     .res_y = 10,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -326,8 +320,6 @@ TEST(HapticButtonGeneratorFilterInterpreterTest, DynamicThresholdTest) {
     .right = 100, .bottom = 100,
     .res_x = 10,
     .res_y = 10,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -407,8 +399,6 @@ TEST(HapticButtonGeneratorFilterInterpreterTest, PalmTest) {
     .right = 100, .bottom = 100,
     .res_x = 10,
     .res_y = 10,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
diff --git a/src/iir_filter_interpreter_unittest.cc b/src/iir_filter_interpreter_unittest.cc
index d1c8b8c..ce5a5b7 100644
--- a/src/iir_filter_interpreter_unittest.cc
+++ b/src/iir_filter_interpreter_unittest.cc
@@ -111,7 +111,6 @@ TEST(IirFilterInterpreterTest, SemiMTIIRTest) {
   HardwareProperties hwprops = {
     .right = 100, .bottom = 60,
     .res_x = 1.0, .res_y = 1.0,
-    .screen_x_dpi = 0, .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 3,
diff --git a/src/immediate_interpreter.cc b/src/immediate_interpreter.cc
index 9f63427..70a8c72 100644
--- a/src/immediate_interpreter.cc
+++ b/src/immediate_interpreter.cc
@@ -268,7 +268,15 @@ ScrollEvent ScrollEvent::Add(const ScrollEvent& evt_a,
   return ret;
 }
 
-void ScrollEventBuffer::Insert(float dx, float dy, float dt) {
+void ScrollEventBuffer::Insert(float dx, float dy, stime_t timestamp,
+                               stime_t prev_timestamp) {
+  float dt;
+  if (size_ > 0) {
+    dt = timestamp - last_scroll_timestamp_;
+  } else {
+    dt = timestamp - prev_timestamp;
+  }
+  last_scroll_timestamp_ = timestamp;
   head_ = (head_ + max_size_ - 1) % max_size_;
   buf_[head_].dx = dx;
   buf_[head_].dy = dy;
@@ -527,7 +535,7 @@ bool ScrollManager::FillResultScroll(
       !FloatEq(dx, 0.0) || !FloatEq(dy, 0.0))
     scroll_buffer->Insert(
         dx, dy,
-        state_buffer.Get(0).timestamp - state_buffer.Get(1).timestamp);
+        state_buffer.Get(0).timestamp, state_buffer.Get(1).timestamp);
   return true;
 }
 
diff --git a/src/immediate_interpreter_unittest.cc b/src/immediate_interpreter_unittest.cc
index 994b11c..dc7e3a5 100644
--- a/src/immediate_interpreter_unittest.cc
+++ b/src/immediate_interpreter_unittest.cc
@@ -29,7 +29,7 @@ TEST(ImmediateInterpreterTest, ScrollEventTest) {
   EXPECT_EQ(33.0, ev3.dt);
 
   ScrollEventBuffer evbuf(2);
-  evbuf.Insert(1.0, 2.0, 3.0);
+  evbuf.Insert(1.0, 2.0, 3.0, 0.0);
   ev1 = evbuf.Get(0);
   EXPECT_EQ(1.0, ev1.dx);
   EXPECT_EQ(2.0, ev1.dy);
@@ -66,8 +66,6 @@ TEST(ImmediateInterpreterTest, MoveDownTest) {
     .bottom = 1000,
     .res_x = 500,
     .res_y = 500,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -128,8 +126,6 @@ TEST(ImmediateInterpreterTest, MoveUpWithRestingThumbTest) {
     .bottom = 1000,
     .res_x = 50,
     .res_y = 50,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -192,8 +188,6 @@ TEST(ImmediateInterpreterTest, SemiMtScrollUpWithRestingThumbTest) {
     .bottom = 1000,
     .res_x = 20,
     .res_y = 20,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -251,8 +245,6 @@ void ScrollUpTest(float pressure_a, float pressure_b) {
     .bottom = 1000,
     .res_x = 20,
     .res_y = 20,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -323,8 +315,6 @@ TEST(ImmediateInterpreterTest, ScrollThenFalseTapTest) {
     .bottom = 1000,
     .res_x = 20,
     .res_y = 20,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -392,8 +382,6 @@ TEST(ImmediateInterpreterTest, FlingTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -504,8 +492,6 @@ TEST(ImmediateInterpreterTest, DelayedStartScrollTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -563,8 +549,6 @@ TEST(ImmediateInterpreterTest, ScrollReevaluateTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -636,8 +620,6 @@ TEST(ImmediateInterpreterTest, OneFingerThenTwoDelayedStartScrollTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -716,8 +698,6 @@ TEST(ImmediateInterpreterTest, OneFatFingerScrollTest) {
     .bottom = 68.000000,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 15,
@@ -884,8 +864,6 @@ TEST(ImmediateInterpreterTest, NoLiftoffScrollTest) {
     .bottom = 68.000000,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 15,
@@ -1020,8 +998,6 @@ TEST(ImmediateInterpreterTest, DiagonalSnapTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -1132,8 +1108,6 @@ TEST(ImmediateInterpreterTest, RestingFingerTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -1200,8 +1174,6 @@ TEST(ImmediateInterpreterTest, ThumbRetainTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -1252,8 +1224,6 @@ TEST(ImmediateInterpreterTest, ThumbRetainReevaluateTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -1301,8 +1271,6 @@ TEST(ImmediateInterpreterTest, SetHardwarePropertiesTwiceTest) {
     .bottom = 1000,
     .res_x = 500,
     .res_y = 500,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -1341,8 +1309,6 @@ TEST(ImmediateInterpreterTest, AmbiguousPalmCoScrollTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5,
@@ -1424,8 +1390,6 @@ TEST(ImmediateInterpreterTest, PressureChangeMoveTest) {
     .bottom = 1000,
     .res_x = 500,
     .res_y = 500,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -1485,8 +1449,6 @@ TEST(ImmediateInterpreterTest, GetGesturingFingersTest) {
     .bottom = 1000,
     .res_x = 500,
     .res_y = 500,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -1846,8 +1808,6 @@ protected:
     .bottom = 200,
     .res_x = 1.0,  // pixels/TP width
     .res_y = 1.0,  // pixels/TP height
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5,
@@ -2689,8 +2649,6 @@ TEST(ImmediateInterpreterTest, TapToClickLowPressureBeginOrEndTest) {
     .bottom = 68.000000,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 15,
@@ -2777,8 +2735,6 @@ TEST(ImmediateInterpreterTest, TapToClickKeyboardTest) {
     .bottom = 200,
     .res_x = 1.0,
     .res_y = 1.0,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5,
@@ -2873,8 +2829,6 @@ TEST_P(ImmediateInterpreterTtcEnableTest, TapToClickEnableTest) {
     .bottom = 200,
     .res_x = 1.0,
     .res_y = 1.0,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5,
@@ -3026,8 +2980,6 @@ TEST(ImmediateInterpreterTest, ClickTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -3118,8 +3070,6 @@ TEST(ImmediateInterpreterTest, BigHandsRightClickTest) {
     .bottom = 68.000000,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 15,
@@ -3271,8 +3221,6 @@ TEST(ImmediateInterpreterTest, ChangeTimeoutTest) {
     .bottom = 1000,
     .res_x = 500,
     .res_y = 500,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -3376,8 +3324,6 @@ TEST(ImmediateInterpreterTest, PinchTests) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -3521,8 +3467,6 @@ TEST(ImmediateInterpreterTest, AvoidAccidentalPinchTest) {
     .bottom = 68.000000,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 15,
@@ -3677,8 +3621,6 @@ TEST(ImmediateInterpreterTest, SemiMtActiveAreaTest) {
     .bottom = 48.953846,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -3725,8 +3667,6 @@ TEST(ImmediateInterpreterTest, SemiMtActiveAreaTest) {
     .bottom = 57.492310,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -3775,8 +3715,6 @@ TEST(ImmediateInterpreterTest, SemiMtNoPinchTest) {
     .bottom = 48.953846,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -3851,8 +3789,6 @@ TEST(ImmediateInterpreterTest, WarpedFingersTappingTest) {
     .bottom = 48.953846,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -3911,8 +3847,6 @@ TEST(ImmediateInterpreterTest, FlingDepthTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -3987,7 +3921,7 @@ TEST(ImmediateInterpreterTest, FlingDepthTest) {
       float dx = fs->position_x - prev_fs->position_x;
       float dy = fs->position_y - prev_fs->position_y;
       float dt = hs->timestamp - prev_hs->timestamp;
-      ii.scroll_buffer_.Insert(dx, dy, dt);
+      ii.scroll_buffer_.Insert(dx, dy, hs->timestamp, prev_hs->timestamp);
       // Enforce assumption that all scrolls are positive in Y only
       EXPECT_DOUBLE_EQ(dx, 0);
       EXPECT_GT(dy, 0);
@@ -4008,8 +3942,6 @@ TEST(ImmediateInterpreterTest, ScrollResetTapTest) {
     .bottom = 57.492310,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -4077,8 +4009,6 @@ TEST(ImmediateInterpreterTest, ZeroClickInitializationTest) {
     .bottom = 1000,
     .res_x = 500,
     .res_y = 500,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
diff --git a/src/interpreter_unittest.cc b/src/interpreter_unittest.cc
index ff5e785..4f13f47 100644
--- a/src/interpreter_unittest.cc
+++ b/src/interpreter_unittest.cc
@@ -83,8 +83,6 @@ TEST(InterpreterTest, SimpleTest) {
     .right = 100, .bottom = 100,
     .res_x = 10,
     .res_y = 10,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = 1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
diff --git a/src/logging_filter_interpreter_unittest.cc b/src/logging_filter_interpreter_unittest.cc
index fb4ebaa..28e000f 100644
--- a/src/logging_filter_interpreter_unittest.cc
+++ b/src/logging_filter_interpreter_unittest.cc
@@ -55,8 +55,6 @@ TEST(LoggingFilterInterpreterTest, LogResetHandlerTest) {
     .right = 100, .bottom = 100,
     .res_x = 10,
     .res_y = 10,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
diff --git a/src/lookahead_filter_interpreter_unittest.cc b/src/lookahead_filter_interpreter_unittest.cc
index 5aed753..83b9241 100644
--- a/src/lookahead_filter_interpreter_unittest.cc
+++ b/src/lookahead_filter_interpreter_unittest.cc
@@ -100,8 +100,6 @@ TEST_P(LookaheadFilterInterpreterParmTest, SimpleTest) {
     .right = 100, .bottom = 100,
     .res_x = 10,
     .res_y = 10,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -247,8 +245,6 @@ TEST(LookaheadFilterInterpreterTest, VariableDelayTest) {
     .right = 100, .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5, .max_touch_cnt = 5,
@@ -324,8 +320,6 @@ TEST(LookaheadFilterInterpreterTest, NoTapSetTest) {
     .right = 100, .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5, .max_touch_cnt = 5,
@@ -380,8 +374,6 @@ TEST(LookaheadFilterInterpreterTest, SpuriousCallbackTest) {
     .right = 100, .bottom = 100,
     .res_x = 10,
     .res_y = 10,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -434,8 +426,6 @@ TEST(LookaheadFilterInterpreterTest, TimeGoesBackwardsTest) {
     .right = 100, .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -530,8 +520,6 @@ TEST(LookaheadFilterInterpreterTest, InterpolateTest) {
     .right = 100, .bottom = 100,
     .res_x = 10,
     .res_y = 10,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -612,8 +600,6 @@ TEST(LookaheadFilterInterpreterTest, InterpolationOverdueTest) {
     .right = 10, .bottom = 10,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -688,8 +674,6 @@ TEST(LookaheadFilterInterpreterTest, DrumrollTest) {
     .right = 100, .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -765,8 +749,6 @@ TEST(LookaheadFilterInterpreterTest, QuickMoveTest) {
     .right = 100, .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -863,8 +845,6 @@ TEST(LookaheadFilterInterpreterTest, QuickSwipeTest) {
     .bottom = 65.259262,
     .res_x = 1.000000,
     .res_y = 1.000000,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -958,8 +938,6 @@ TEST(LookaheadFilterInterpreterTest, CyapaDrumrollTest) {
     .bottom = 68.000000,
     .res_x = 1.000000,
     .res_y = 1.000000,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 15,
@@ -1166,8 +1144,6 @@ TEST(LookaheadFilterInterpreterTest, CyapaQuickTwoFingerMoveTest) {
     .bottom = 68.000000,
     .res_x = 1.000000,
     .res_y = 1.000000,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 15,
@@ -1228,8 +1204,6 @@ TEST(LookaheadFilterInterpreterTest, SemiMtNoTrackingIdAssignmentTest) {
     .right = 100, .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -1297,8 +1271,6 @@ TEST(LookaheadFilterInterpreterTest, AddFingerFlingTest) {
     .right = 100, .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -1356,8 +1328,6 @@ TEST(LookaheadFilterInterpreterTest, ConsumeGestureTest) {
     .right = 100, .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
diff --git a/src/metrics_filter_interpreter_unittest.cc b/src/metrics_filter_interpreter_unittest.cc
index f078aa3..d690df9 100644
--- a/src/metrics_filter_interpreter_unittest.cc
+++ b/src/metrics_filter_interpreter_unittest.cc
@@ -14,7 +14,6 @@ namespace {
 const HardwareProperties hwprops = {
   .right = 100, .bottom = 100,
   .res_x = 1, .res_y = 1,
-  .screen_x_dpi = 0, .screen_y_dpi = 0,
   .orientation_minimum = -1,
   .orientation_maximum = 2,
   .max_finger_cnt = 5, .max_touch_cnt = 5,
diff --git a/src/mouse_interpreter_unittest.cc b/src/mouse_interpreter_unittest.cc
index 520a455..8f5b032 100644
--- a/src/mouse_interpreter_unittest.cc
+++ b/src/mouse_interpreter_unittest.cc
@@ -18,8 +18,6 @@ HardwareProperties make_hwprops_for_mouse(
     .bottom = 0,
     .res_x = 0,
     .res_y = 0,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = 0,
     .orientation_maximum = 0,
     .max_finger_cnt = 0,
diff --git a/src/multitouch_mouse_interpreter_unittest.cc b/src/multitouch_mouse_interpreter_unittest.cc
index ba23e40..7ff6a49 100644
--- a/src/multitouch_mouse_interpreter_unittest.cc
+++ b/src/multitouch_mouse_interpreter_unittest.cc
@@ -21,8 +21,6 @@ TEST(MultitouchMouseInterpreterTest, SimpleTest) {
     .left = 133, .top = 728, .right = 10279, .bottom = 5822,
     .res_x = (10279.0 - 133.0) / 100.0,
     .res_y = (5822.0 - 728.0) / 60,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
diff --git a/src/palm_classifying_filter_interpreter_unittest.cc b/src/palm_classifying_filter_interpreter_unittest.cc
index 61c1c88..6d667ad 100644
--- a/src/palm_classifying_filter_interpreter_unittest.cc
+++ b/src/palm_classifying_filter_interpreter_unittest.cc
@@ -51,8 +51,6 @@ TEST(PalmClassifyingFilterInterpreterTest, PalmTest) {
     .bottom = 1000,
     .res_x = 500,
     .res_y = 500,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -131,8 +129,6 @@ TEST(PalmClassifyingFilterInterpreterTest, ExternallyMarkedPalmTest) {
     .bottom = 1000,
     .res_x = 500,
     .res_y = 500,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2,
@@ -193,8 +189,6 @@ TEST(PalmClassifyingFilterInterpreterTest, StationaryPalmTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5,
@@ -252,8 +246,6 @@ TEST(PalmClassifyingFilterInterpreterTest, PalmAtEdgeTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5,
@@ -379,8 +371,6 @@ TEST(PalmClassifyingFilterInterpreterTest, PalmReevaluateTest) {
     .bottom = 68.000000,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 15,
@@ -468,8 +458,6 @@ TEST(PalmClassifyingFilterInterpreterTest, LargeTouchMajorTest) {
     .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5,
diff --git a/src/scaling_filter_interpreter.cc b/src/scaling_filter_interpreter.cc
index 6045801..64ec328 100644
--- a/src/scaling_filter_interpreter.cc
+++ b/src/scaling_filter_interpreter.cc
@@ -373,8 +373,6 @@ void ScalingFilterInterpreter::Initialize(const HardwareProperties* hwprops,
   friendly_props_.bottom = (hwprops->bottom - hwprops->top) * tp_y_scale_;
   friendly_props_.res_x = 1.0;  // X pixels/mm
   friendly_props_.res_y = 1.0;  // Y pixels/mm
-  friendly_props_.screen_x_dpi = 25.4;
-  friendly_props_.screen_y_dpi = 25.4;
   friendly_props_.orientation_minimum = friendly_orientation_minimum;
   friendly_props_.orientation_maximum = friendly_orientation_maximum;
 
diff --git a/src/scaling_filter_interpreter_unittest.cc b/src/scaling_filter_interpreter_unittest.cc
index 6d1c529..69f61f5 100644
--- a/src/scaling_filter_interpreter_unittest.cc
+++ b/src/scaling_filter_interpreter_unittest.cc
@@ -133,8 +133,6 @@ TEST(ScalingFilterInterpreterTest, SimpleTest) {
     .left = 133, .top = 728, .right = 10279, .bottom = 5822,
     .res_x = (10279.0 - 133.0) / 100.0,
     .res_y = (5822.0 - 728.0) / 60,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -146,8 +144,6 @@ TEST(ScalingFilterInterpreterTest, SimpleTest) {
     .right = 100, .bottom = 60,
     .res_x = 1.0,
     .res_y = 1.0,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -M_PI_4,  // (1 tick above X-axis)
     .orientation_maximum = M_PI_2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -283,7 +279,6 @@ TEST(ScalingFilterInterpreterTest, ResolutionFallback) {
   HardwareProperties initial_hwprops = {
     .right = 2000, .bottom = 1000,
     .res_x = 0, .res_y = 0,
-    .screen_x_dpi = 0, .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -294,7 +289,6 @@ TEST(ScalingFilterInterpreterTest, ResolutionFallback) {
   HardwareProperties expected_hwprops = {
     .right = 2000 / 32.0, .bottom = 1000 / 32.0,
     .res_x = 1, .res_y = 1,
-    .screen_x_dpi = 0, .screen_y_dpi = 0,
     .orientation_minimum = -M_PI_4,  // (1 tick above X-axis)
     .orientation_maximum = M_PI_2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -436,8 +430,6 @@ TEST(ScalingFilterInterpreterTest, TouchMajorAndMinorTest) {
     .right = 500, .bottom = 1000,
     .res_x = 5,
     .res_y = 10,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -31,
     .orientation_maximum = 32,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
@@ -448,7 +440,6 @@ TEST(ScalingFilterInterpreterTest, TouchMajorAndMinorTest) {
   HardwareProperties expected_hwprops = {
     .right = 100, .bottom = 100,
     .res_x = 1.0, .res_y = 1.0,
-    .screen_x_dpi = 0, .screen_y_dpi = 0,
     .orientation_minimum = -M_PI * 31 / 64,  // (1 tick above X-axis)
     .orientation_maximum = M_PI_2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
diff --git a/src/sensor_jump_filter_interpreter_unittest.cc b/src/sensor_jump_filter_interpreter_unittest.cc
index 64a13e5..4ec5b21 100644
--- a/src/sensor_jump_filter_interpreter_unittest.cc
+++ b/src/sensor_jump_filter_interpreter_unittest.cc
@@ -61,7 +61,6 @@ TEST(SensorJumpFilterInterpreterTest, SimpleTest) {
   HardwareProperties hwprops = {
     .right = 100, .bottom = 100,
     .res_x = 1, .res_y = 1,
-    .screen_x_dpi = 0, .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5, .max_touch_cnt = 5,
@@ -124,7 +123,6 @@ TEST(SensorJumpFilterInterpreterTest, ActualLogTest) {
   HardwareProperties hwprops = {
     .right = 106.666672, .bottom = 68,
     .res_x = 1, .res_y = 1,
-    .screen_x_dpi = 0, .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 15, .max_touch_cnt = 5,
diff --git a/src/split_correcting_filter_interpreter_unittest.cc b/src/split_correcting_filter_interpreter_unittest.cc
index a0c6ea8..a7a82ff 100644
--- a/src/split_correcting_filter_interpreter_unittest.cc
+++ b/src/split_correcting_filter_interpreter_unittest.cc
@@ -73,8 +73,6 @@ void DoTest(InputEventWithExpectations* events, size_t events_len, bool t5r2) {
     .right = 100, .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5,
@@ -170,8 +168,6 @@ TEST(SplitCorrectingFilterInterpreterTest, FalseMergeTest) {
     .right = 100, .bottom = 100,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5,
@@ -187,14 +183,15 @@ TEST(SplitCorrectingFilterInterpreterTest, FalseMergeTest) {
 
   for (size_t i = 0; i < arraysize(inputs); i++) {
     const FalseMergeInputs& input = inputs[i];
+    const size_t max_finger_cnt = arraysize(input.in);
     // Get finger count
     unsigned short finger_cnt = 0;
     for (size_t fidx = 0;
-         fidx < arraysize(input.in) && input.in[fidx].id_ >= 0;
+         fidx < max_finger_cnt && input.in[fidx].id_ >= 0;
          fidx++)
       finger_cnt += 1;
     // Set up hardware state
-    FingerState fs[finger_cnt];
+    FingerState fs[max_finger_cnt];
     for (size_t fidx = 0; fidx < finger_cnt; fidx++) {
       memset(&fs[fidx], 0, sizeof(fs[fidx]));
       fs[fidx].position_x  = input.in[fidx].x_;
@@ -327,8 +324,6 @@ TEST(SplitCorrectingFilterInterpreterTest, LumpyThumbSplitTest) {
     .bottom = 68.0,
     .res_x = 1.0,
     .res_y = 1.0,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 15,
diff --git a/src/stationary_wiggle_filter_interpreter_unittest.cc b/src/stationary_wiggle_filter_interpreter_unittest.cc
index 1ac5e9b..048e6c4 100644
--- a/src/stationary_wiggle_filter_interpreter_unittest.cc
+++ b/src/stationary_wiggle_filter_interpreter_unittest.cc
@@ -61,7 +61,6 @@ TEST(StationaryWiggleFilterInterpreterTest, SimpleTest) {
   HardwareProperties hwprops = {
     .right = 100, .bottom = 100,
     .res_x = 1, .res_y = 1,
-    .screen_x_dpi = 0, .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5, .max_touch_cnt = 5,
diff --git a/src/stuck_button_inhibitor_filter_interpreter_unittest.cc b/src/stuck_button_inhibitor_filter_interpreter_unittest.cc
index f983f28..0bdd80e 100644
--- a/src/stuck_button_inhibitor_filter_interpreter_unittest.cc
+++ b/src/stuck_button_inhibitor_filter_interpreter_unittest.cc
@@ -82,8 +82,6 @@ TEST(StuckButtonInhibitorFilterInterpreterTest, SimpleTest) {
     .right = 100, .bottom = 100,
     .res_x = 10,
     .res_y = 10,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
diff --git a/src/t5r2_correcting_filter_interpreter_unittest.cc b/src/t5r2_correcting_filter_interpreter_unittest.cc
index c297457..590ac98 100644
--- a/src/t5r2_correcting_filter_interpreter_unittest.cc
+++ b/src/t5r2_correcting_filter_interpreter_unittest.cc
@@ -71,8 +71,6 @@ TEST(T5R2CorrectingFilterInterpreterTest, SimpleTest) {
     .right = 10, .bottom = 10,
     .res_x = 1,
     .res_y = 1,
-    .screen_x_dpi = 0,
-    .screen_y_dpi = 0,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 2, .max_touch_cnt = 5,
diff --git a/src/trend_classifying_filter_interpreter_unittest.cc b/src/trend_classifying_filter_interpreter_unittest.cc
index 80e069e..bd7b316 100644
--- a/src/trend_classifying_filter_interpreter_unittest.cc
+++ b/src/trend_classifying_filter_interpreter_unittest.cc
@@ -46,7 +46,6 @@ TEST(TrendClassifyingFilterInterpreterTest, SimpleTest) {
   HardwareProperties hwprops = {
     .right = 100, .bottom = 100,
     .res_x = 1, .res_y = 1,
-    .screen_x_dpi = 1, .screen_y_dpi = 1,
     .orientation_minimum = -1,
     .orientation_maximum = 2,
     .max_finger_cnt = 5, .max_touch_cnt = 5,
diff --git a/tools/regression_test.sh b/tools/regression_test.sh
index f97118a..0cb10d4 100755
--- a/tools/regression_test.sh
+++ b/tools/regression_test.sh
@@ -7,6 +7,9 @@
 # Script to run the gesture regression test and check if there is any
 # regression for each submit.
 
+# Exit on errors.
+set -eu
+
 # Set current directory to the project one and load the common script.
 pushd . >/dev/null
 cd "$(dirname "$(readlink -f "$0")")/.."
@@ -31,7 +34,7 @@ update_chroot_library() {
 install_regression_test_suite() {
   info "Install regression test suite first..."
   sudo emerge -q gestures chromeos-base/libevdev utouch-evemu -j3
-  pushd ~/trunk/src/platform/touchpad-tests >/dev/null
+  pushd ~/chromiumos/src/platform/touchpad-tests >/dev/null
   make -j${NUM_JOBS} -s all
   sudo make -s local-install
   popd >/dev/null
diff --git a/tools/touchtests-report.json b/tools/touchtests-report.json
index 145f6aa..76f71cb 100644
--- a/tools/touchtests-report.json
+++ b/tools/touchtests-report.json
@@ -897,10 +897,10 @@
   },
   "gnawty-elan-4.0/baseline/drag": {
     "description": "",
-    "disabled": false,
+    "disabled": true,
     "error": "",
-    "result": "success",
-    "score": 0.997738329781867
+    "result": "incomplete",
+    "score": 0
   },
   "gnawty-elan-4.0/baseline/fling": {
     "description": "",
@@ -3701,5 +3701,54 @@
     "error": "",
     "result": "failure",
     "score": false
+  },
+  "xol-1.0/baseline/click": {
+    "description": "",
+    "disabled": true,
+    "error": "",
+    "result": "incomplete",
+    "score": 0
+  },
+  "xol-1.0/baseline/drag": {
+    "description": "",
+    "disabled": true,
+    "error": "",
+    "result": "incomplete",
+    "score": 0
+  },
+  "xol-1.0/baseline/fling": {
+    "description": "",
+    "disabled": true,
+    "error": "",
+    "result": "incomplete",
+    "score": 0
+  },
+  "xol-1.0/baseline/move": {
+    "description": "",
+    "disabled": true,
+    "error": "",
+    "result": "incomplete",
+    "score": 0
+  },
+  "xol-1.0/baseline/scroll": {
+    "description": "",
+    "disabled": true,
+    "error": "",
+    "result": "incomplete",
+    "score": 0
+  },
+  "xol-1.0/baseline/tap": {
+    "description": "",
+    "disabled": true,
+    "error": "",
+    "result": "incomplete",
+    "score": 0
+  },
+  "xol-1.0/unexpected_flings": {
+    "description": "",
+    "disabled": false,
+    "error": "",
+    "result": "success",
+    "score": 1
   }
 }
```

