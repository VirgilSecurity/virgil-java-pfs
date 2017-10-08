package com.virgilsecurity.sdk.securechat.session;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.securechat.model.CardEntry;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

public class SessionInitializerTest {

	private Crypto crypto;
	private SessionInitializer sessionInitializer;

	@Before
	public void setUp() {
		this.crypto = new VirgilCrypto();

		CardModel card = new CardModel();
		card.setSnapshot(ConvertionUtils.base64ToBytes(
				"eyJpZCI6IjExOWU4ZGIxMjg0MGNkODllYjY3YzY4OGM0NTFiMTA4ZmYwZmQ1M2VmMThjNjZlZDQ1NWQ3NTcwODc5Njc1NWEiLCJjb250ZW50X3NuYXBzaG90IjoiZXlKcFpHVnVkR2wwZVNJNkltUmhabUZtYjNCdlFERXlhRzl6ZEdsdVp5NXVaWFFpTENKcFpHVnVkR2wwZVY5MGVYQmxJam9pWlcxaGFXd2lMQ0p3ZFdKc2FXTmZhMlY1SWpvaVRVTnZkMEpSV1VSTE1sWjNRWGxGUVdaVU0yaFdObmwwWEM5dVFtbDRkRU5wU2xkQmRXSjFPRTVFYzNadFRXUjRVR1Y2ZEZKcUswaExaV2gzUFNJc0luTmpiM0JsSWpvaVoyeHZZbUZzSW4wPSIsIm1ldGEiOnsic2lnbnMiOnsiMTE5ZThkYjEyODQwY2Q4OWViNjdjNjg4YzQ1MWIxMDhmZjBmZDUzZWYxOGM2NmVkNDU1ZDc1NzA4Nzk2NzU1YSI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFMVlg3QUVMUDN4NEl4dDJVOUNkSlFQUCtydk5aTjhtTGRsSlJmazlpOTlXdVZJcENoWWtua052Y0NSVnlMNUxtY2wvNEJlOHlKc1E1VFkvYUVwb1pBND0iLCI2N2I4ZWU4ZTUzYjRjMGM2YjY1YjRiYmRkYTZmYTE1OWU4MjA4ZjU4ZmZjMjkwZWM2MWE3MmMzZmQwN2FkMDM1IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUtrR1pSRnVBMSsrdzc1NTZtVFBNL2FRaUc1MjhlamQ5Y3d3NGtxTkU3d1BrTnZBOXFxV1hJbWIwdlNGb0w3cXM4VFBNMm5YS2ZBUkdHU3NaMXBQOXdrPSIsIjNlMjlkNDMzNzMzNDhjZmIzNzNiN2VhZTE4OTIxNGRjMDFkNzIzNzc2NWU1NzJkYjY4NTgzOWI2NGFkY2E4NTMiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRSC9xbzdFeVI1WlEwZ0ZkV0RwRlZMS0hhUkZ6dkhUTit3SUpSR1pqZDhKbWFYbk8vYTJ6OVF4K2xvTVloZEFoQXg5QXpROVlkcnJDTzBOVldqd080QUU9In0sImNyZWF0ZWRfYXQiOiIyMDE3LTAzLTEzVDEzOjIwOjAwKzAyOjAwIiwiY2FyZF92ZXJzaW9uIjoiNC4wIn19"));
		this.sessionInitializer = new SessionInitializer(this.crypto, this.crypto.generateKeys().getPrivateKey(), card);
	}

	@Test
	public void initializeInitiator() {
		PrivateKey ephPrivateKey = this.crypto.generateKeys().getPrivateKey();
		CardEntry idEntry = new CardEntry(UUID.randomUUID().toString(),
				this.crypto.exportPublicKey(this.crypto.generateKeys().getPublicKey()));
		CardEntry ltEntry = new CardEntry(UUID.randomUUID().toString(),
				this.crypto.exportPublicKey(this.crypto.generateKeys().getPublicKey()));
		CardEntry otEntry = new CardEntry(UUID.randomUUID().toString(),
				this.crypto.exportPublicKey(this.crypto.generateKeys().getPublicKey()));

		byte[] additionalData = UUID.randomUUID().toString().getBytes();

		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.SECOND, 10);
		Date expirationDate = calendar.getTime();

		SecureSession session = this.sessionInitializer.initializeInitiatorSession(ephPrivateKey, idEntry, ltEntry,
				otEntry, additionalData, expirationDate);

		assertNotNull(session);
		assertNotNull(session.getIdentifier());
		assertTrue(session.getIdentifier().length > 0);
		assertEquals(expirationDate, session.getExpirationDate());
		assertNotNull(session.getDecryptionKey());
		assertTrue(session.getDecryptionKey().length > 0);
		assertNotNull(session.getEncryptionKey());
		assertTrue(session.getEncryptionKey().length > 0);
		assertNotNull(session.getAdditionalData());
		assertTrue(session.getAdditionalData().length > 0);

		assertFalse(session.isExpired());
		calendar.add(Calendar.SECOND, -1);
		assertFalse(session.isExpired(calendar.getTime()));
		calendar.add(Calendar.SECOND, 2);
		assertTrue(session.isExpired(calendar.getTime()));
	}

	@Test
	public void initializeInitiatorWeak() {
		PrivateKey ephPrivateKey = this.crypto.generateKeys().getPrivateKey();
		CardEntry idEntry = new CardEntry(UUID.randomUUID().toString(),
				this.crypto.exportPublicKey(this.crypto.generateKeys().getPublicKey()));
		CardEntry ltEntry = new CardEntry(UUID.randomUUID().toString(),
				this.crypto.exportPublicKey(this.crypto.generateKeys().getPublicKey()));
		CardEntry otEntry = new CardEntry(UUID.randomUUID().toString(),
				this.crypto.exportPublicKey(this.crypto.generateKeys().getPublicKey()));

		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.SECOND, 10);
		Date expirationDate = calendar.getTime();

		SecureSession session = this.sessionInitializer.initializeInitiatorSession(ephPrivateKey, idEntry, ltEntry,
				otEntry, null, expirationDate);

		assertNotNull(session);
		assertNotNull(session.getIdentifier());
		assertTrue(session.getIdentifier().length > 0);
		assertEquals(expirationDate, session.getExpirationDate());
		assertNotNull(session.getDecryptionKey());
		assertTrue(session.getDecryptionKey().length > 0);
		assertNotNull(session.getEncryptionKey());
		assertTrue(session.getEncryptionKey().length > 0);
		assertNotNull(session.getAdditionalData());
		assertTrue(session.getAdditionalData().length > 0);

		assertFalse(session.isExpired());
		calendar.add(Calendar.SECOND, -1);
		assertFalse(session.isExpired(calendar.getTime()));
		calendar.add(Calendar.SECOND, 2);
		assertTrue(session.isExpired(calendar.getTime()));
	}

	@Test
	public void initializeResponder() {
		PrivateKey idPrivateKey = this.crypto.generateKeys().getPrivateKey();
		CardEntry idEntry = new CardEntry(UUID.randomUUID().toString(),
				this.crypto.exportPublicKey(this.crypto.extractPublicKey(idPrivateKey)));
		PrivateKey privateKey = this.crypto.generateKeys().getPrivateKey();
		PrivateKey ltKey = this.crypto.generateKeys().getPrivateKey();
		byte[] ephPublicKeyData = this.crypto.exportPublicKey(this.crypto.generateKeys().getPublicKey());

		byte[] additionalData = UUID.randomUUID().toString().getBytes();

		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.SECOND, 10);
		Date expirationDate = calendar.getTime();

		SecureSession session = this.sessionInitializer.initializeResponderSession(idEntry, privateKey, ltKey, null,
				ephPublicKeyData, additionalData, expirationDate);

		assertNotNull(session);
		assertNotNull(session.getIdentifier());
		assertTrue(session.getIdentifier().length > 0);
		assertEquals(expirationDate, session.getExpirationDate());
		assertNotNull(session.getDecryptionKey());
		assertTrue(session.getDecryptionKey().length > 0);
		assertNotNull(session.getEncryptionKey());
		assertTrue(session.getEncryptionKey().length > 0);
		assertNotNull(session.getAdditionalData());
		assertTrue(session.getAdditionalData().length > 0);

		assertFalse(session.isExpired());
		calendar.add(Calendar.SECOND, -1);
		assertFalse(session.isExpired(calendar.getTime()));
		calendar.add(Calendar.SECOND, 2);
		assertTrue(session.isExpired(calendar.getTime()));
	}

	@Test
	public void initializeResponderWeak() {
		PrivateKey idPrivateKey = this.crypto.generateKeys().getPrivateKey();
		CardEntry idEntry = new CardEntry(UUID.randomUUID().toString(),
				this.crypto.exportPublicKey(this.crypto.extractPublicKey(idPrivateKey)));
		PrivateKey privateKey = this.crypto.generateKeys().getPrivateKey();
		PrivateKey ltKey = this.crypto.generateKeys().getPrivateKey();
		byte[] ephPublicKeyData = this.crypto.exportPublicKey(this.crypto.generateKeys().getPublicKey());

		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.SECOND, 10);
		Date expirationDate = calendar.getTime();

		SecureSession session = this.sessionInitializer.initializeResponderSession(idEntry, privateKey, ltKey, null,
				ephPublicKeyData, null, expirationDate);

		assertNotNull(session);
		assertNotNull(session.getIdentifier());
		assertTrue(session.getIdentifier().length > 0);
		assertEquals(expirationDate, session.getExpirationDate());
		assertNotNull(session.getDecryptionKey());
		assertTrue(session.getDecryptionKey().length > 0);
		assertNotNull(session.getEncryptionKey());
		assertTrue(session.getEncryptionKey().length > 0);
		assertNotNull(session.getAdditionalData());
		assertTrue(session.getAdditionalData().length > 0);

		assertFalse(session.isExpired());
		calendar.add(Calendar.SECOND, -1);
		assertFalse(session.isExpired(calendar.getTime()));
		calendar.add(Calendar.SECOND, 2);
		assertTrue(session.isExpired(calendar.getTime()));
	}

	@Test
	public void initializeSaved() {
		byte[] sessionId = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);
		byte[] encryptionKey = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);
		byte[] decryptionKey = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);
		byte[] additionalData = Arrays.copyOf(UUID.randomUUID().toString().getBytes(), 16);

		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.SECOND, 10);
		Date expirationDate = calendar.getTime();

		SecureSession session = this.sessionInitializer.initializeSavedSession(sessionId, encryptionKey, decryptionKey,
				additionalData, expirationDate);

		assertArrayEquals(sessionId, session.getIdentifier());
		assertArrayEquals(encryptionKey, session.getEncryptionKey());
		assertArrayEquals(decryptionKey, session.getDecryptionKey());
		assertArrayEquals(additionalData, session.getAdditionalData());

		assertFalse(session.isExpired());
		calendar.add(Calendar.SECOND, -1);
		assertFalse(session.isExpired(calendar.getTime()));
		calendar.add(Calendar.SECOND, 2);
		assertTrue(session.isExpired(calendar.getTime()));
	}

}
