```diff
diff --git a/Android.bp b/Android.bp
index d8ac05d..082af5b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -39,6 +39,7 @@ cc_defaults {
         "-D_FILE_OFFSET_BITS=64",
         "-DGESTURES_INTERNAL=1",
     ],
+    cpp_std: "c++20",
     sanitize: {
         all_undefined: true,
         integer_overflow: true,
diff --git a/Makefile b/Makefile
index 9adcf1e..65eccc7 100644
--- a/Makefile
+++ b/Makefile
@@ -111,7 +111,7 @@ DESTDIR = .
 
 CXXFLAGS+=\
 	-g \
-	-std=gnu++17 \
+	-std=gnu++20 \
 	-fno-exceptions \
 	-fno-strict-aliasing \
 	-fPIC \
diff --git a/include/eintr_wrapper.h b/include/eintr_wrapper.h
index df2a3aa..0a0fc28 100644
--- a/include/eintr_wrapper.h
+++ b/include/eintr_wrapper.h
@@ -11,7 +11,7 @@
 #include <errno.h>
 
 #define HANDLE_EINTR(x) ({ \
-  typeof(x) eintr_wrapper_result; \
+  decltype(x) eintr_wrapper_result; \
   do { \
     eintr_wrapper_result = (x); \
   } while (eintr_wrapper_result == -1 && errno == EINTR); \
@@ -19,7 +19,7 @@
 })
 
 #define IGNORE_EINTR(x) ({ \
-  typeof(x) eintr_wrapper_result; \
+  decltype(x) eintr_wrapper_result; \
   do { \
     eintr_wrapper_result = (x); \
     if (eintr_wrapper_result == -1 && errno == EINTR) { \
diff --git a/include/immediate_interpreter.h b/include/immediate_interpreter.h
index e414bf7..9f82717 100644
--- a/include/immediate_interpreter.h
+++ b/include/immediate_interpreter.h
@@ -802,6 +802,12 @@ class ImmediateInterpreter : public Interpreter, public PropertyDelegate {
   DoubleProperty change_move_distance_;
   // Speed [mm/s] a finger must move to lock on to that finger
   DoubleProperty move_lock_speed_;
+  // Speed [mm/s] a finger must move to lock on to that finger, when another
+  // finger is already locked.
+  DoubleProperty move_change_lock_speed_;
+  // How much faster a finger must move than the currently locked finger to
+  // switch the lock.
+  DoubleProperty move_change_lock_ratio_;
   // Distance [mm] a finger must move to report that movement
   DoubleProperty move_report_distance_;
   // Time [s] to block movement after number or identify of fingers change
diff --git a/src/gestures.cc b/src/gestures.cc
index f5fbf5e..2907e3e 100644
--- a/src/gestures.cc
+++ b/src/gestures.cc
@@ -87,28 +87,28 @@ std::string HardwareProperties::String() const {
 namespace {
 string NameForFingerStateFlag(unsigned flag) {
 #define CASERET(name)                           \
-  case name: return #name
+  case GESTURES_FINGER_##name: return #name
   switch (flag) {
-    CASERET(GESTURES_FINGER_WARP_X_NON_MOVE);
-    CASERET(GESTURES_FINGER_WARP_Y_NON_MOVE);
-    CASERET(GESTURES_FINGER_NO_TAP);
-    CASERET(GESTURES_FINGER_POSSIBLE_PALM);
-    CASERET(GESTURES_FINGER_PALM);
-    CASERET(GESTURES_FINGER_WARP_X_MOVE);
-    CASERET(GESTURES_FINGER_WARP_Y_MOVE);
-    CASERET(GESTURES_FINGER_WARP_X_TAP_MOVE);
-    CASERET(GESTURES_FINGER_WARP_Y_TAP_MOVE);
-    CASERET(GESTURES_FINGER_MERGE);
-    CASERET(GESTURES_FINGER_TREND_INC_X);
-    CASERET(GESTURES_FINGER_TREND_DEC_X);
-    CASERET(GESTURES_FINGER_TREND_INC_Y);
-    CASERET(GESTURES_FINGER_TREND_DEC_Y);
-    CASERET(GESTURES_FINGER_TREND_INC_PRESSURE);
-    CASERET(GESTURES_FINGER_TREND_DEC_PRESSURE);
-    CASERET(GESTURES_FINGER_TREND_INC_TOUCH_MAJOR);
-    CASERET(GESTURES_FINGER_TREND_DEC_TOUCH_MAJOR);
-    CASERET(GESTURES_FINGER_INSTANTANEOUS_MOVING);
-    CASERET(GESTURES_FINGER_WARP_TELEPORTATION);
+    CASERET(WARP_X_NON_MOVE);
+    CASERET(WARP_Y_NON_MOVE);
+    CASERET(NO_TAP);
+    CASERET(POSSIBLE_PALM);
+    CASERET(PALM);
+    CASERET(WARP_X_MOVE);
+    CASERET(WARP_Y_MOVE);
+    CASERET(WARP_X_TAP_MOVE);
+    CASERET(WARP_Y_TAP_MOVE);
+    CASERET(MERGE);
+    CASERET(TREND_INC_X);
+    CASERET(TREND_DEC_X);
+    CASERET(TREND_INC_Y);
+    CASERET(TREND_DEC_Y);
+    CASERET(TREND_INC_PRESSURE);
+    CASERET(TREND_DEC_PRESSURE);
+    CASERET(TREND_INC_TOUCH_MAJOR);
+    CASERET(TREND_DEC_TOUCH_MAJOR);
+    CASERET(INSTANTANEOUS_MOVING);
+    CASERET(WARP_TELEPORTATION);
   }
 #undef CASERET
   return "";
@@ -134,21 +134,21 @@ string FingerState::FlagsString(unsigned flags) {
     // strip extra pipe
     ret = ret.substr(strlen(kPipeSeparator));
   } else {
-    ret = "0";
+    ret = "no flags";
   }
   return ret;
 }
 
 string FingerState::String() const {
-  return StringPrintf("{ %f, %f, %f, %f, %f, %f, %f, %f, %d, %s }",
+  return StringPrintf("{ %d: (%.2f, %.2f), touch %.2fx%.2f, width %.2fx%.2f, "
+                      "pressure %.2f, orient %.2f%s }",
+                      tracking_id,
+                      position_x, position_y,
                       touch_major, touch_minor,
                       width_major, width_minor,
                       pressure,
                       orientation,
-                      position_x,
-                      position_y,
-                      tracking_id,
-                      FlagsString(flags).c_str());
+                      flags ? (", " + FlagsString(flags)).c_str() : "");
 }
 
 FingerState* HardwareState::GetFingerState(short tracking_id) {
@@ -165,7 +165,7 @@ const FingerState* HardwareState::GetFingerState(short tracking_id) const {
 }
 
 string HardwareState::String() const {
-  string ret = StringPrintf("{ %f, %d, %d, %d, {",
+  string ret = StringPrintf("{ %f, buttons 0x%x, %d f, %d t, {",
                             timestamp,
                             buttons_down,
                             finger_cnt,
@@ -245,8 +245,9 @@ string Gesture::String() const {
                           details.pinch.zoom_state);
     case kGestureTypeButtonsChange:
       return StringPrintf("(Gesture type: buttons start: %f stop: "
-                          "%f down: %d up: %d)", start_time, end_time,
-                          details.buttons.down, details.buttons.up);
+                          "%f down: %d up: %d is_tap: %s)", start_time, end_time,
+                          details.buttons.down, details.buttons.up,
+                          details.buttons.is_tap ? "true" : "false");
     case kGestureTypeFling:
       return StringPrintf("(Gesture type: fling start: %f stop: "
                           "%f vx: %f vy: %f ordinal_dx: %f ordinal_dy: %f "
diff --git a/src/gestures_unittest.cc b/src/gestures_unittest.cc
index 3d56a69..0edf870 100644
--- a/src/gestures_unittest.cc
+++ b/src/gestures_unittest.cc
@@ -412,15 +412,15 @@ TEST(GesturesTest, StimeFromTimespecTest) {
 }
 
 TEST(GesturesTest, FingerStateFlagsStringTest) {
-  EXPECT_EQ("0", FingerState::FlagsString(0));
-  EXPECT_EQ("GESTURES_FINGER_PALM",
+  EXPECT_EQ("no flags", FingerState::FlagsString(0));
+  EXPECT_EQ("PALM",
             FingerState::FlagsString(GESTURES_FINGER_PALM));
-  EXPECT_EQ("GESTURES_FINGER_PALM | GESTURES_FINGER_WARP_X_MOVE",
+  EXPECT_EQ("PALM | WARP_X_MOVE",
             FingerState::FlagsString(
                 GESTURES_FINGER_PALM | GESTURES_FINGER_WARP_X_MOVE));
   // 1 << 31 probably won't be used as a finger flag value anytime soon, so use
   // it to test prepending the remaining number.
-  EXPECT_EQ("2147483648 | GESTURES_FINGER_PALM",
+  EXPECT_EQ("2147483648 | PALM",
             FingerState::FlagsString(GESTURES_FINGER_PALM | (1 << 31)));
 }
 
@@ -503,8 +503,8 @@ TEST(GesturesTest, HardwareStateToStringTest) {
     "20.0",
     "30.0",
     "14",
-    "GESTURES_FINGER_WARP_Y_NON_MOVE",
-    "GESTURES_FINGER_PALM",
+    "WARP_Y_NON_MOVE",
+    "PALM",
     "1.5",
     "2.5",
     "3.5",
@@ -514,24 +514,31 @@ TEST(GesturesTest, HardwareStateToStringTest) {
     "20.5",
     "30.5",
     "15",
-    "GESTURES_FINGER_WARP_X_NON_MOVE",
+    "WARP_X_NON_MOVE",
     "1.123",
-    "1, 2, 2"
+    "buttons 0x1",
+    "2 f",
+    "2 t",
   };
   const char* short_expected[] = {
     "2.123",
-    "0, 0, 0",
-    "{}"
+    "buttons 0x0",
+    "0 f",
+    "0 t",
+    "{}",
   };
   string long_str = hs[0].String();
   string short_str = hs[1].String();
 
-  for (size_t i = 0; i < arraysize(expected); i++)
+  for (size_t i = 0; i < arraysize(expected); i++) {
     EXPECT_NE(nullptr, strstr(long_str.c_str(), expected[i]))
-        << " str: " << expected[i];
-  for (size_t i = 0; i < arraysize(short_expected); i++)
+        << "\"" << long_str << "\" should contain \"" << expected[i] << "\"";
+  }
+  for (size_t i = 0; i < arraysize(short_expected); i++) {
     EXPECT_NE(nullptr, strstr(short_str.c_str(), short_expected[i]))
-        << " str: " << short_expected[i];
+        << "\"" << short_str << "\" should contain \"" << short_expected[i]
+        << "\"";
+  }
 
   return;
 }
diff --git a/src/immediate_interpreter.cc b/src/immediate_interpreter.cc
index 70a8c72..3302789 100644
--- a/src/immediate_interpreter.cc
+++ b/src/immediate_interpreter.cc
@@ -1033,6 +1033,8 @@ ImmediateInterpreter::ImmediateInterpreter(PropRegistry* prop_reg,
                                       false),
       change_move_distance_(prop_reg, "Change Min Move Distance", 3.0),
       move_lock_speed_(prop_reg, "Move Lock Speed", 10.0),
+      move_change_lock_speed_(prop_reg, "Move Change Lock Speed", 20.0),
+      move_change_lock_ratio_(prop_reg, "Move Change Lock Ratio", 2.0),
       move_report_distance_(prop_reg, "Move Report Distance", 0.35),
       change_timeout_(prop_reg, "Change Timeout", 0.2),
       evaluation_timeout_(prop_reg, "Evaluation Timeout", 0.15),
@@ -3156,39 +3158,82 @@ void ImmediateInterpreter::FillResultGesture(
       if (fingers.empty())
         return;
       // Use the finger which has moved the most to compute motion.
-      // First, need to find out which finger that is.
+      // First, check if we have locked onto a fast finger in the past.
       const FingerState* current = nullptr;
       if (moving_finger_id_ >= 0)
         current = hwstate.GetFingerState(moving_finger_id_);
 
+      // Determine which finger is moving fastest.
+      const FingerState* fastest = nullptr;
       const HardwareState& prev_hs = state_buffer_.Get(1);
-      if (!current) {
-        float curr_dist_sq = -1;
-        for (short tracking_id : fingers) {
-          const FingerState* fs = hwstate.GetFingerState(tracking_id);
-          const FingerState* prev_fs = prev_hs.GetFingerState(fs->tracking_id);
-          if (!prev_fs)
-            break;
-          float dist_sq = DistSq(*fs, *prev_fs);
-          if (dist_sq > curr_dist_sq) {
-            current = fs;
-            curr_dist_sq = dist_sq;
-          }
+      float curr_dist_sq = -1;
+      for (short tracking_id : fingers) {
+        const FingerState* fs = hwstate.GetFingerState(tracking_id);
+        const FingerState* prev_fs = prev_hs.GetFingerState(fs->tracking_id);
+        if (!prev_fs)
+          break;
+        float dist_sq = DistSq(*fs, *prev_fs);
+        if (dist_sq > curr_dist_sq) {
+          fastest = fs;
+          curr_dist_sq = dist_sq;
         }
       }
+
+      if (!current)
+        current = fastest;
       if (!current)
         return;
 
-      // Find corresponding finger id in previous state
       const FingerState* prev =
           state_buffer_.Get(1).GetFingerState(current->tracking_id);
+      if (!prev)
+        return;
+
+      float dx = current->position_x - prev->position_x;
+      if (current->flags & GESTURES_FINGER_WARP_X_MOVE)
+        dx = 0.0;
+      float dy = current->position_y - prev->position_y;
+      if (current->flags & GESTURES_FINGER_WARP_Y_MOVE)
+        dy = 0.0;
+      float dsq = dx * dx + dy * dy;
+      stime_t dt = hwstate.timestamp - state_buffer_.Get(1).timestamp;
+
+      // If we are locked on to a finger that is not the fastest moving,
+      // determine if we want to switch the lock to the fastest finger.
+      const FingerState* prev_fastest = nullptr;
+      if (fastest) {
+          prev_fastest =
+              state_buffer_.Get(1).GetFingerState(fastest->tracking_id);
+      }
+      if (prev_fastest && fastest != current) {
+        float fastest_dx = fastest->position_x - prev_fastest->position_x;
+        if (fastest->flags & GESTURES_FINGER_WARP_X_MOVE)
+          fastest_dx = 0.0;
+        float fastest_dy = fastest->position_y - prev_fastest->position_y;
+        if (fastest->flags & GESTURES_FINGER_WARP_Y_MOVE)
+          fastest_dy = 0.0;
+        float fastest_dsq = fastest_dx * fastest_dx + fastest_dy * fastest_dy;
+
+        float change_lock_dsq_thresh =
+            (move_change_lock_speed_.val_ * move_change_lock_speed_.val_) *
+            (dt * dt);
+        if (fastest_dsq > dsq * move_change_lock_ratio_.val_ &&
+            fastest_dsq > change_lock_dsq_thresh) {
+          moving_finger_id_ = fastest->tracking_id;
+          current = fastest;
+          dx = fastest_dx;
+          dy = fastest_dy;
+          dsq = fastest_dsq;
+          prev = prev_fastest;
+        }
+      }
+
       const FingerState* prev2 =
           state_buffer_.Get(2).GetFingerState(current->tracking_id);
       if (!prev || !current)
         return;
       if (current->flags & GESTURES_FINGER_MERGE)
         return;
-      stime_t dt = hwstate.timestamp - state_buffer_.Get(1).timestamp;
       bool suppress_finger_movement =
           scroll_manager_.SuppressStationaryFingerMovement(
               *current, *prev, dt) ||
@@ -3216,13 +3261,6 @@ void ImmediateInterpreter::FillResultGesture(
         return;
       }
       scroll_manager_.prev_result_suppress_finger_movement_ = false;
-      float dx = current->position_x - prev->position_x;
-      if (current->flags & GESTURES_FINGER_WARP_X_MOVE)
-        dx = 0.0;
-      float dy = current->position_y - prev->position_y;
-      if (current->flags & GESTURES_FINGER_WARP_Y_MOVE)
-        dy = 0.0;
-      float dsq = dx * dx + dy * dy;
       float dx_total = current->position_x -
                        start_positions_[current->tracking_id].x_;
       float dy_total = current->position_y -
diff --git a/src/immediate_interpreter_unittest.cc b/src/immediate_interpreter_unittest.cc
index dc7e3a5..f086ab8 100644
--- a/src/immediate_interpreter_unittest.cc
+++ b/src/immediate_interpreter_unittest.cc
@@ -3054,6 +3054,92 @@ TEST(ImmediateInterpreterTest, ClickTest) {
   }
 }
 
+struct ClickDragLockInputAndExpectations {
+  HardwareState hs;
+  stime_t timeout;
+  unsigned expected_down;
+  unsigned expected_up;
+  bool expected_move;
+};
+
+TEST(ImmediateInterpreterTest, ClickDragLockTest) {
+  ImmediateInterpreter ii(nullptr, nullptr);
+  HardwareProperties hwprops = {
+    .right = 100,
+    .bottom = 100,
+    .res_x = 1,
+    .res_y = 1,
+    .orientation_minimum = -1,
+    .orientation_maximum = 2,
+    .max_finger_cnt = 2,
+    .max_touch_cnt = 5,
+    .supports_t5r2 = 0,
+    .support_semi_mt = 0,
+    .is_button_pad = 1,
+    .has_wheel = 0,
+    .wheel_is_hi_res = 0,
+    .is_haptic_pad = 0,
+  };
+  TestInterpreterWrapper wrapper(&ii, &hwprops);
+
+  FingerState finger_states[] = {
+    // TM, Tm, WM, Wm, Press, Orientation, X, Y, TrID
+    {0, 0, 0, 0, 10, 0, 50, 50, 1, 0},
+    {0, 0, 0, 0, 10, 0, 70, 50, 2, 0},
+    // One finger moves fast enough to lock on.
+    {0, 0, 0, 0, 10, 0, 45, 50, 1, 0},
+    {0, 0, 0, 0, 10, 0, 70, 50, 2, 0},
+    // Second finger moves, but not fast enough to break lock.
+    {0, 0, 0, 0, 10, 0, 45, 50, 1, 0},
+    {0, 0, 0, 0, 10, 0, 71, 50, 2, 0},
+    // Second finger moves fast enough to break lock.
+    {0, 0, 0, 0, 10, 0, 45, 50, 1, 0},
+    {0, 0, 0, 0, 10, 0, 76, 50, 2, 0},
+    // First finger moves, but not fast enough to break lock.
+    {0, 0, 0, 0, 10, 0, 44, 50, 1, 0},
+    {0, 0, 0, 0, 10, 0, 76, 50, 2, 0},
+  };
+  ClickDragLockInputAndExpectations records[] = {
+    // reset
+    {make_hwstate(0,0,0,0,nullptr),NO_DEADLINE,0,0,false},
+
+    {make_hwstate(1,1,0,0,nullptr),NO_DEADLINE,0,0,false},
+    {make_hwstate(1.01,1,2,2,&finger_states[0]), NO_DEADLINE, 0, 0, false},
+    {make_hwstate(2,1,2,2,&finger_states[0]),
+     NO_DEADLINE, GESTURES_BUTTON_RIGHT, 0, false},
+    {make_hwstate(2.1,1,2,2,&finger_states[2]), NO_DEADLINE, 0, 0, true},
+    {make_hwstate(2.2,1,2,2,&finger_states[4]), NO_DEADLINE, 0, 0, false},
+    {make_hwstate(2.3,1,2,2,&finger_states[6]), NO_DEADLINE, 0, 0, true},
+    {make_hwstate(2.4,1,2,2,&finger_states[8]), NO_DEADLINE, 0, 0, false},
+    {make_hwstate(3,0,0,0,nullptr),
+     NO_DEADLINE, 0, GESTURES_BUTTON_RIGHT, false},
+
+    {make_hwstate(10,0,0,0,nullptr), NO_DEADLINE, 0, 0, false}
+  };
+
+  for (size_t i = 0; i < arraysize(records); ++i) {
+    Gesture* result = nullptr;
+    if (records[i].timeout < 0.0)
+      result = wrapper.SyncInterpret(records[i].hs, nullptr);
+    else
+      result = wrapper.HandleTimer(records[i].timeout, nullptr);
+    if (records[i].expected_move) {
+      ASSERT_NE(nullptr, result) << "i=" << i;
+      EXPECT_EQ(result->type, kGestureTypeMove);
+      EXPECT_NE(result->details.move.dx, 0.0);
+    } else if (records[i].expected_down != 0 || records[i].expected_up != 0) {
+      ASSERT_NE(nullptr, result) << "i=" << i;
+      EXPECT_EQ(records[i].expected_down, result->details.buttons.down);
+      EXPECT_EQ(records[i].expected_up, result->details.buttons.up);
+    } else {
+      if (result) {
+        EXPECT_EQ(result->type, kGestureTypeMove);
+        EXPECT_EQ(result->details.move.dx, 0.0);
+      }
+    }
+  }
+}
+
 struct BigHandsRightClickInputAndExpectations {
   HardwareState hs;
   unsigned out_buttons_down;
diff --git a/tools/touchtests-report.json b/tools/touchtests-report.json
index 76f71cb..fabe5d7 100644
--- a/tools/touchtests-report.json
+++ b/tools/touchtests-report.json
@@ -3744,6 +3744,20 @@
     "result": "incomplete",
     "score": 0
   },
+  "xol-1.0/click_drag_1": {
+    "description": "",
+    "disabled": false,
+    "error": "",
+    "result": "success",
+    "score": 1.0
+  },
+  "xol-1.0/click_drag_2": {
+    "description": "",
+    "disabled": false,
+    "error": "",
+    "result": "success",
+    "score": 1.0
+  },
   "xol-1.0/unexpected_flings": {
     "description": "",
     "disabled": false,
```

