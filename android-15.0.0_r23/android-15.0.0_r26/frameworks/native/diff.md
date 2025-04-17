```diff
diff --git a/services/surfaceflinger/FrontEnd/LayerSnapshotBuilder.cpp b/services/surfaceflinger/FrontEnd/LayerSnapshotBuilder.cpp
index 4d9a9ca06e..34b1307d46 100644
--- a/services/surfaceflinger/FrontEnd/LayerSnapshotBuilder.cpp
+++ b/services/surfaceflinger/FrontEnd/LayerSnapshotBuilder.cpp
@@ -1162,7 +1162,7 @@ void LayerSnapshotBuilder::updateInput(LayerSnapshot& snapshot,
     auto displayInfo = displayInfoOpt.value_or(sDefaultInfo);
 
     if (!requested.hasInputInfo()) {
-        snapshot.inputInfo.inputConfig = InputConfig::NO_INPUT_CHANNEL;
+        snapshot.inputInfo.inputConfig |= InputConfig::NO_INPUT_CHANNEL;
     }
     fillInputFrameInfo(snapshot.inputInfo, displayInfo.transform, snapshot);
 
diff --git a/services/surfaceflinger/FrontEnd/RequestedLayerState.cpp b/services/surfaceflinger/FrontEnd/RequestedLayerState.cpp
index ee9302b937..88924193c8 100644
--- a/services/surfaceflinger/FrontEnd/RequestedLayerState.cpp
+++ b/services/surfaceflinger/FrontEnd/RequestedLayerState.cpp
@@ -561,7 +561,7 @@ bool RequestedLayerState::needsInputInfo() const {
         return false;
     }
 
-    if ((sidebandStream != nullptr) || (externalTexture != nullptr)) {
+    if (hasBufferOrSidebandStream() || fillsColor()) {
         return true;
     }
 
@@ -574,6 +574,15 @@ bool RequestedLayerState::needsInputInfo() const {
             windowInfo->inputConfig.test(gui::WindowInfo::InputConfig::NO_INPUT_CHANNEL);
 }
 
+bool RequestedLayerState::hasBufferOrSidebandStream() const {
+    return ((sidebandStream != nullptr) || (externalTexture != nullptr));
+}
+
+bool RequestedLayerState::fillsColor() const {
+    return !hasBufferOrSidebandStream() && color.r >= 0.0_hf && color.g >= 0.0_hf &&
+            color.b >= 0.0_hf;
+}
+
 bool RequestedLayerState::hasBlur() const {
     return backgroundBlurRadius > 0 || blurRegions.size() > 0;
 }
diff --git a/services/surfaceflinger/FrontEnd/RequestedLayerState.h b/services/surfaceflinger/FrontEnd/RequestedLayerState.h
index 7ddd7baf1e..f974ed3a5a 100644
--- a/services/surfaceflinger/FrontEnd/RequestedLayerState.h
+++ b/services/surfaceflinger/FrontEnd/RequestedLayerState.h
@@ -88,6 +88,8 @@ struct RequestedLayerState : layer_state_t {
     bool hasValidRelativeParent() const;
     bool hasInputInfo() const;
     bool needsInputInfo() const;
+    bool hasBufferOrSidebandStream() const;
+    bool fillsColor() const;
     bool hasBlur() const;
     bool hasFrameUpdate() const;
     bool hasReadyFrame() const;
diff --git a/services/surfaceflinger/tests/unittests/LayerLifecycleManagerTest.cpp b/services/surfaceflinger/tests/unittests/LayerLifecycleManagerTest.cpp
index c7cc21ce07..119e182769 100644
--- a/services/surfaceflinger/tests/unittests/LayerLifecycleManagerTest.cpp
+++ b/services/surfaceflinger/tests/unittests/LayerLifecycleManagerTest.cpp
@@ -619,14 +619,32 @@ TEST_F(LayerLifecycleManagerTest, isSimpleBufferUpdate) {
     }
 }
 
-TEST_F(LayerLifecycleManagerTest, testInputInfoOfRequestedLayerState) {
-    // By default the layer has no buffer, so it doesn't need an input info
-    EXPECT_FALSE(getRequestedLayerState(mLifecycleManager, 111)->needsInputInfo());
+TEST_F(LayerLifecycleManagerTest, layerWithBufferNeedsInputInfo) {
+    // If a layer has no buffer or no color, it doesn't have an input info
+    LayerHierarchyTestBase::createRootLayer(3);
+    setColor(3, {-1._hf, -1._hf, -1._hf});
+    mLifecycleManager.commitChanges();
+
+    EXPECT_FALSE(getRequestedLayerState(mLifecycleManager, 3)->needsInputInfo());
+
+    setBuffer(3);
+    mLifecycleManager.commitChanges();
+
+    EXPECT_TRUE(getRequestedLayerState(mLifecycleManager, 3)->needsInputInfo());
+}
+
+TEST_F(LayerLifecycleManagerTest, layerWithColorNeedsInputInfo) {
+    // If a layer has no buffer or no color, it doesn't have an input info
+    LayerHierarchyTestBase::createRootLayer(4);
+    setColor(4, {-1._hf, -1._hf, -1._hf});
+    mLifecycleManager.commitChanges();
+
+    EXPECT_FALSE(getRequestedLayerState(mLifecycleManager, 4)->needsInputInfo());
 
-    setBuffer(111);
+    setColor(4, {1._hf, 0._hf, 0._hf});
     mLifecycleManager.commitChanges();
 
-    EXPECT_TRUE(getRequestedLayerState(mLifecycleManager, 111)->needsInputInfo());
+    EXPECT_TRUE(getRequestedLayerState(mLifecycleManager, 4)->needsInputInfo());
 }
 
 } // namespace android::surfaceflinger::frontend
diff --git a/services/surfaceflinger/tests/unittests/LayerSnapshotTest.cpp b/services/surfaceflinger/tests/unittests/LayerSnapshotTest.cpp
index 8c53eef01a..bb54138de0 100644
--- a/services/surfaceflinger/tests/unittests/LayerSnapshotTest.cpp
+++ b/services/surfaceflinger/tests/unittests/LayerSnapshotTest.cpp
@@ -1957,17 +1957,17 @@ TEST_F(LayerSnapshotTest, multipleEdgeExtensionIncreaseBoundSizeWithinCrop) {
 }
 
 TEST_F(LayerSnapshotTest, shouldUpdateInputWhenNoInputInfo) {
-    // By default the layer has no buffer, so we don't expect it to have an input info
+    // If a layer has no buffer or no color, it doesn't have an input info
+    setColor(111, {-1._hf, -1._hf, -1._hf});
+    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 11, 12, 121, 122, 1221, 13, 2});
     EXPECT_FALSE(getSnapshot(111)->hasInputInfo());
 
     setBuffer(111);
-
     UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
 
     EXPECT_TRUE(getSnapshot(111)->hasInputInfo());
     EXPECT_TRUE(getSnapshot(111)->inputInfo.inputConfig.test(
             gui::WindowInfo::InputConfig::NO_INPUT_CHANNEL));
-    EXPECT_FALSE(getSnapshot(2)->hasInputInfo());
 }
 
 // content dirty test
```

