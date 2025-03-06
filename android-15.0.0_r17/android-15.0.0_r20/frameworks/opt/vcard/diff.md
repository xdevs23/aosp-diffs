```diff
diff --git a/java/com/android/vcard/VCardEntry.java b/java/com/android/vcard/VCardEntry.java
index 8054bb7..04b7b24 100644
--- a/java/com/android/vcard/VCardEntry.java
+++ b/java/com/android/vcard/VCardEntry.java
@@ -1752,7 +1752,15 @@ public class VCardEntry {
     }
 
     private final int mVCardType;
-    private final Account mAccount;
+    private Account mAccount;
+
+    public Account getAccount() {
+        return mAccount;
+    }
+
+    public void setAccount(Account account) {
+        mAccount = account;
+    }
 
     private List<VCardEntry> mChildren;
 
diff --git a/tests/src/com/android/vcard/tests/VCardEntryTests.java b/tests/src/com/android/vcard/tests/VCardEntryTests.java
index 32b3eaa..69bd058 100644
--- a/tests/src/com/android/vcard/tests/VCardEntryTests.java
+++ b/tests/src/com/android/vcard/tests/VCardEntryTests.java
@@ -38,6 +38,7 @@ import com.android.vcard.VCardEntryHandler;
 import com.android.vcard.VCardInterpreter;
 import com.android.vcard.VCardProperty;
 
+import android.accounts.Account;
 import android.content.ContentProviderOperation;
 import android.content.ContentResolver;
 import android.provider.ContactsContract.CommonDataKinds.Email;
@@ -374,5 +375,62 @@ public class VCardEntryTests extends AndroidTestCase {
         assertEquals(0, operationList.size());
     }
 
+    /**
+     * Tests that VCardEntry can add an account via the constructor
+     */
+    public void testConstructor_withAccount_canGetAccount() {
+        Account account = new Account("test-type", "test-name");
+        VCardEntry entry = new VCardEntry(VCardConfig.VCARD_TYPE_V21_GENERIC, account);
+        assertEquals(entry.getAccount(), account);
+    }
+
+    /**
+     * Tests that VCardEntry can add a null account via the constructor
+     */
+    public void testConstructor_withNullAccount_canGetNullAccount() {
+        VCardEntry entry = new VCardEntry(VCardConfig.VCARD_TYPE_V21_GENERIC, null);
+        assertEquals(entry.getAccount(), null);
+    }
+
+    /**
+     * Tests that VCardEntry can add an account via the setter, updating a null account to a value
+     */
+    public void testSetAccount_fromNullToValue_canGetAccount() {
+        Account account = new Account("test-type", "test-name");
+        VCardEntry entry = new VCardEntry();
+        assertEquals(entry.getAccount(), null);
+        entry.setAccount(account);
+        assertEquals(entry.getAccount(), account);
+    }
+
+    /**
+     * Tests that VCardEntry can add an account via the setter, changing one account to another
+     */
+    public void testSetAccount_fromToNewValue_canGetAccount() {
+        Account account1 = new Account("test-type-1", "test-name-1");
+        VCardEntry entry = new VCardEntry(VCardConfig.VCARD_TYPE_V21_GENERIC, account1);
+        assertEquals(entry.getAccount(), account1);
+
+        Account account2 = new Account("test-type-2", "test-name-2");
+        entry.setAccount(account2);
+        assertEquals(entry.getAccount(), account2);
+    }
+
+    /**
+     * Tests that VCardEntry can add an account via the setter, changing one account to another
+     */
+    public void testSetAccount_setValueTwice_canGetAccount() {
+        VCardEntry entry = new VCardEntry();
+        assertEquals(entry.getAccount(), null);
+
+        Account account1 = new Account("test-type-1", "test-name-1");
+        entry.setAccount(account1);
+        assertEquals(entry.getAccount(), account1);
+
+        Account account2 = new Account("test-type-2", "test-name-2");
+        entry.setAccount(account2);
+        assertEquals(entry.getAccount(), account2);
+    }
+
     // TODO: add bunch of test for constructInsertOperations..
-}
\ No newline at end of file
+}
```

