package com.virgilsecurity.sdk.securechat;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.securechat.KeyStorageManager.HelperKeyEntry;
import com.virgilsecurity.sdk.securechat.KeyStorageManager.SessionKeys;
import com.virgilsecurity.sdk.securechat.keystorage.JsonFileKeyStorage;
import com.virgilsecurity.sdk.securechat.keystorage.KeyAttrs;
import com.virgilsecurity.sdk.securechat.keystorage.KeyStorage;

public class KeyStorageManagerTest {

	private Crypto crypto;
	private KeyStorageManager keyStorageManager;

	@Before
	public void setUp() {
		this.crypto = new VirgilCrypto();
		KeyStorage keyStorage = new JsonFileKeyStorage(System.getProperty("java.io.tmpdir"),
				UUID.randomUUID().toString());
		this.keyStorageManager = new KeyStorageManager(this.crypto, keyStorage, UUID.randomUUID().toString());
	}

	@Test
	public void hasRelevantLtKey() throws CryptoException {
		assertFalse(keyStorageManager.hasRelevantLtKey(5));

		String ltPrivateKeyName = UUID.randomUUID().toString();
		HelperKeyEntry ltKey = new KeyStorageManager.HelperKeyEntry(crypto.generateKeys().getPrivateKey(),
				ltPrivateKeyName);
		keyStorageManager.saveKeys(Collections.EMPTY_LIST, ltKey);

		PrivateKey key = keyStorageManager.getLtPrivateKey(ltPrivateKeyName);
		assertNotNull(key);

		assertTrue(keyStorageManager.hasRelevantLtKey(5));

		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.SECOND, 6);
		assertFalse(keyStorageManager.hasRelevantLtKey(cal.getTime(), 5));
	}

	@Test
	public void ltKeys() throws InterruptedException, CryptoException {
		String ltName1 = UUID.randomUUID().toString();
		String ltName2 = UUID.randomUUID().toString();

		keyStorageManager.saveKeys(Collections.EMPTY_LIST,
				new KeyStorageManager.HelperKeyEntry(crypto.generateKeys().getPrivateKey(), ltName1));

		PrivateKey ltPrivate1 = keyStorageManager.getLtPrivateKey(ltName1);
		assertTrue(keyStorageManager.hasRelevantLtKey(5));

		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.SECOND, 6);
		assertFalse(keyStorageManager.hasRelevantLtKey(cal.getTime(), 5));

		Thread.sleep(3000);

		keyStorageManager.saveKeys(Collections.EMPTY_LIST,
				new KeyStorageManager.HelperKeyEntry(crypto.generateKeys().getPrivateKey(), ltName2));
		PrivateKey ltPrivate2 = keyStorageManager.getLtPrivateKey(ltName2);

		assertTrue(keyStorageManager.hasRelevantLtKey(5));

		cal = Calendar.getInstance();
		cal.add(Calendar.SECOND, 1);
		assertTrue(keyStorageManager.hasRelevantLtKey(cal.getTime(), 5));

		cal.add(Calendar.SECOND, 5);
		assertFalse(keyStorageManager.hasRelevantLtKey(cal.getTime(), 5));

		keyStorageManager.removeLtPrivateKeys(Arrays.asList(ltName1));
		try {
			keyStorageManager.getLtPrivateKey(ltName1);
			fail();
		} catch (KeyEntryNotFoundException e) {
		}

		assertTrue(keyStorageManager.hasRelevantLtKey(5));

		cal = Calendar.getInstance();
		cal.add(Calendar.SECOND, 1);
		assertTrue(keyStorageManager.hasRelevantLtKey(cal.getTime(), 5));
		cal.add(Calendar.SECOND, 5);
		assertFalse(keyStorageManager.hasRelevantLtKey(cal.getTime(), 5));

		keyStorageManager.removeLtPrivateKeys(Arrays.asList(ltName2));
		assertFalse(keyStorageManager.hasRelevantLtKey(5));

		try {
			keyStorageManager.getLtPrivateKey(ltName2);
			fail();
		} catch (KeyEntryNotFoundException e) {
		}
	}

	@Test
	public void sessionKeys1() {
		byte[] sessionId = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);
		byte[] encryptionKey = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);
		byte[] decryptionKey = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);

		SessionKeys sessionKeys0 = new KeyStorageManager.SessionKeys(encryptionKey, decryptionKey);
		keyStorageManager.saveSessionKeys(sessionKeys0, sessionId);

		SessionKeys sessionKeys1 = keyStorageManager.getSessionKeys(sessionId);

		assertNotNull(sessionKeys1);
		assertArrayEquals(encryptionKey, sessionKeys1.getEncryptionKey());
		assertArrayEquals(decryptionKey, sessionKeys1.getDecryptionKey());

		keyStorageManager.removeSessionKeys(sessionId);
		try {
			keyStorageManager.getSessionKeys(sessionId);
			fail();
		} catch (KeyEntryNotFoundException e) {
		}
	}

	@Test
	public void sessionKeys2() {
		byte[] sessionId1 = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);
		byte[] sessionId2 = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);
		byte[] encryptionKey = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);
		byte[] decryptionKey = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);

		SessionKeys sessionKeys0 = new KeyStorageManager.SessionKeys(encryptionKey, decryptionKey);
		keyStorageManager.saveSessionKeys(sessionKeys0, sessionId1);

		assertEquals(1, keyStorageManager.getAllKeysAttrs().get("session").size());

		keyStorageManager.saveSessionKeys(sessionKeys0, sessionId2);
		assertEquals(2, keyStorageManager.getAllKeysAttrs().get("session").size());

		SessionKeys sessionKeys11 = keyStorageManager.getSessionKeys(sessionId1);
		SessionKeys sessionKeys12 = keyStorageManager.getSessionKeys(sessionId2);

		assertArrayEquals(encryptionKey, sessionKeys11.getEncryptionKey());
		assertArrayEquals(decryptionKey, sessionKeys11.getDecryptionKey());

		assertArrayEquals(encryptionKey, sessionKeys12.getEncryptionKey());
		assertArrayEquals(decryptionKey, sessionKeys12.getDecryptionKey());

		keyStorageManager.removeSessionKeys(Arrays.asList(sessionId1, sessionId2));
		assertTrue(keyStorageManager.getAllKeysAttrs().get("session").isEmpty());

		try {
			keyStorageManager.getSessionKeys(sessionId1);
			fail();
		} catch (KeyEntryNotFoundException e) {
		}
		try {
			keyStorageManager.getSessionKeys(sessionId2);
			fail();
		} catch (KeyEntryNotFoundException e) {
		}
	}

	@Test
	public void otKeys() throws CryptoException {
		HelperKeyEntry keyEntry1 = new KeyStorageManager.HelperKeyEntry(crypto.generateKeys().getPrivateKey(),
				UUID.randomUUID().toString());
		HelperKeyEntry keyEntry2 = new KeyStorageManager.HelperKeyEntry(crypto.generateKeys().getPrivateKey(),
				UUID.randomUUID().toString());
		HelperKeyEntry keyEntry3 = new KeyStorageManager.HelperKeyEntry(crypto.generateKeys().getPrivateKey(),
				UUID.randomUUID().toString());

		keyStorageManager.saveKeys(Arrays.asList(keyEntry1, keyEntry2, keyEntry3), null);

		assertEquals(3, keyStorageManager.getAllKeysAttrs().get("ot").size());

		keyStorageManager.getOtPrivateKey(keyEntry1.getName());
		keyStorageManager.getOtPrivateKey(keyEntry2.getName());
		keyStorageManager.getOtPrivateKey(keyEntry3.getName());

		keyStorageManager.removeOtPrivateKey(keyEntry1.getName());

		try {
			keyStorageManager.getOtPrivateKey(keyEntry1.getName());
			fail();
		} catch (KeyEntryNotFoundException e) {
		}

		keyStorageManager.getOtPrivateKey(keyEntry2.getName());
		keyStorageManager.getOtPrivateKey(keyEntry3.getName());

		assertEquals(2, keyStorageManager.getAllKeysAttrs().get("ot").size());

		keyStorageManager.removeOtPrivateKeys(Arrays.asList(keyEntry2.getName(), keyEntry3.getName()));

		try {
			keyStorageManager.getOtPrivateKey(keyEntry1.getName());
			fail();
		} catch (KeyEntryNotFoundException e) {
		}
		try {
			keyStorageManager.getOtPrivateKey(keyEntry2.getName());
		} catch (KeyEntryNotFoundException e) {
		}
		try {
			keyStorageManager.getOtPrivateKey(keyEntry3.getName());
		} catch (KeyEntryNotFoundException e) {
		}
		assertTrue(keyStorageManager.getAllKeysAttrs().get("ot").isEmpty());
	}

	@Test
	public void gentleReset() throws CryptoException {
        byte[] sessionId1 = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);
        byte[] sessionId2 = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);
        byte[] encryptionKey = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);
        byte[] decryptionKey = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);
        
        SessionKeys sessionKeys0 = new KeyStorageManager.SessionKeys(encryptionKey, decryptionKey);
        keyStorageManager.saveSessionKeys(sessionKeys0, sessionId1);
        assertEquals(1, keyStorageManager.getAllKeysAttrs().get("session").size());
        
        keyStorageManager.saveSessionKeys(sessionKeys0, sessionId2);
        assertEquals(2, keyStorageManager.getAllKeysAttrs().get("session").size());
        
        HelperKeyEntry keyEntry1 = new KeyStorageManager.HelperKeyEntry(crypto.generateKeys().getPrivateKey(), UUID.randomUUID().toString());
        		HelperKeyEntry keyEntry2 = new KeyStorageManager.HelperKeyEntry(crypto.generateKeys().getPrivateKey(), UUID.randomUUID().toString());
        				HelperKeyEntry keyEntry3 = new KeyStorageManager.HelperKeyEntry(crypto.generateKeys().getPrivateKey(), UUID.randomUUID().toString());
        
        HelperKeyEntry ltKeyEntry = new KeyStorageManager.HelperKeyEntry(crypto.generateKeys().getPrivateKey(), UUID.randomUUID().toString());
        keyStorageManager.saveKeys(Arrays.asList(keyEntry1, keyEntry2, keyEntry3), ltKeyEntry);
        
        keyStorageManager.gentleReset();
       
        
        Map<String, List<KeyAttrs>> map = keyStorageManager.getAllKeysAttrs();
        assertEquals(0,  map.get("session").size());
        assertEquals(0,  map.get("lt").size());
        assertEquals(0,  map.get("ot").size());
        
        try {
            keyStorageManager.getLtPrivateKey(ltKeyEntry.getName());
            fail();
        }
        catch (KeyEntryNotFoundException e) {
        }
        try {
            keyStorageManager.getOtPrivateKey(keyEntry1.getName());
            fail();
        }
        catch (KeyEntryNotFoundException e) {
        }
        try {
            keyStorageManager.getOtPrivateKey(keyEntry2.getName());
            fail();
        }
        catch (KeyEntryNotFoundException e) {
        }
        try {
            keyStorageManager.getOtPrivateKey(keyEntry3.getName());
            fail();
        }
        catch (KeyEntryNotFoundException e) {
        }
        try {
            keyStorageManager.getSessionKeys(sessionId1);
            fail();
        }
        catch (KeyEntryNotFoundException e) {
        }
        try {
            keyStorageManager.getSessionKeys(sessionId2);
            fail();
        }
        catch (KeyEntryNotFoundException e) {
        }
    }
}
