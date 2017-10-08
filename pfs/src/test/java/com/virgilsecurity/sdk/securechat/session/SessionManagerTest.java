package com.virgilsecurity.sdk.securechat.session;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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
import com.virgilsecurity.sdk.pfs.model.RecipientCardsSet;
import com.virgilsecurity.sdk.securechat.Constants;
import com.virgilsecurity.sdk.securechat.KeyStorageManager;
import com.virgilsecurity.sdk.securechat.SessionStorageManager;
import com.virgilsecurity.sdk.securechat.TestUtils;
import com.virgilsecurity.sdk.securechat.exceptions.SessionManagerException;
import com.virgilsecurity.sdk.securechat.impl.DefaultUserDataStorage;
import com.virgilsecurity.sdk.securechat.keystorage.JsonFileKeyStorage;
import com.virgilsecurity.sdk.securechat.keystorage.KeyStorage;
import com.virgilsecurity.sdk.securechat.model.CardEntry;
import com.virgilsecurity.sdk.securechat.model.InitiationMessage;

public class SessionManagerTest {

	private Crypto crypto;
	private CardModel card;
	private KeyStorageManager keyStorageManager;
	private SessionManager sessionManager;
	private int sessionTtl;

	@Before
	public void setUp() {
		this.crypto = new VirgilCrypto();

		this.card = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI3KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUdYWEpDVFdpc25cL1VReUNjM0o3WUk3a1QwcEJzUlJqWFZweVlzcDN3aGRtN0p3YlljN2RTVkdSWXdtaEtWODBjSGVKVUw4S0JvNENzT2Uzb3p5RGhRaz0iLCJhNjY2MzE4MDcxMjc0YWRiNzM4YWYzZjY3YjhjN2VjMjlkOTU0ZGUyY2FiZmQ3MWE5NDJlNmVhMzhlNTlmZmY5IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUURzS3pDQ3Jxb1hlY3Q4V3psVGphRlVXTWkyeEtJYkxKa0Fnd3AyTnBnd3RuYVpoYURsSllMbGh4WDlma25EQTNSRW5nSzBYSExRaG40Zzkxa3NKSmdZPSIsImU2ODBiZWY4N2JhNzVkMzMxYjBhMDJiZmE2YTIwZjAyZWI1YzViYTliYzk2ZmM2MWNhNTk1NDA0YjEwMDI2ZjQiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRRXlobUxHOURiTHBWa3k3c2ttUTVBRTN4T21lMVlpVUpWNjFlemRSZ04rTGlwSmJrclwvclB1VXo3eFJERmUzY294TGM2elRFbUZlK1BqV1BMTnVFcGdrPSJ9fSwiY29udGVudF9zbmFwc2hvdCI6ImV5SndkV0pzYVdOZmEyVjVJam9pVFVOdmQwSlJXVVJMTWxaM1FYbEZRVlZaVTNkQk5XZE9iR2RUVXpSMVQwSlFibmRLVDNOQmFsVkJSSEk1V2xwbFdGWjROakp2YTB0V2RFMDlJaXdpYVdSbGJuUnBkSGtpT2lKQ1JqbEdORFZHUVMwMU9EbEZMVFF6TlRBdE9FVkNRUzAyUWtaRlFVTkNOa05GUTBVaUxDSnBaR1Z1ZEdsMGVWOTBlWEJsSWpvaWRHVnpkQ0lzSW5OamIzQmxJam9pWVhCd2JHbGpZWFJwYjI0aWZRPT0iLCJpZCI6IjhlMWE4NWEwNGEyZWY2MmFjMzkwZDYyYWE5YzQ3ODQ4ZjViMGM3NGNlZTliZjg2NzFkOTI5Y2M1ODU0ZTBhNGEifQ==");

		KeyStorage keyStorage = new JsonFileKeyStorage(System.getProperty("java.io.tmpdir"),
				UUID.randomUUID().toString());
		this.keyStorageManager = new KeyStorageManager(this.crypto, keyStorage, this.card.getId());

		SessionStorageManager sessionStorageManager = new SessionStorageManager(this.card.getId(),
				new DefaultUserDataStorage());

		this.sessionTtl = 10;
		PrivateKey privateKey = this.crypto.generateKeys().getPrivateKey();
		SessionInitializer sessionInitializer = new SessionInitializer(this.crypto, privateKey, this.card);
		this.sessionManager = new SessionManager(this.card, privateKey, this.crypto, this.sessionTtl,
				this.keyStorageManager, sessionStorageManager, sessionInitializer);
	}

	@Test
	public void initializeInitiator() throws SessionManagerException {
		CardModel ltCard = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU1jZWhpXC9ZVXFvZlpVbGdJVmdaRjgzc2ZcL2tObzNNZ0wzQlRmNDVlMWx0eWp1RkhBbWEzMGpCWVBEVDVuY1piQ0gxVXNmekJwbU9US1ZKb2laMXV4ZzQ9IiwiNGYzZWMzY2JlMTFlMTRiY2ZiYjYyNjVhYmYwM2M0YTIxZDYwOThkNGFlZGJjMDZmYjY2OGMyZjYyY2M5M2VmOCI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFEeFJPWFFCV2ZxWjVYdnhlOWRtUlwvWk40akgrNm90eENxWWY3aFcrcDRaN2VVSFhuUytIbDR4MkZibmtFc2xPZDZ0SHRWTGsrRWNvZnBUUWxPNFRad2s9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFUVktOMU00VEhCS1pETnZTbEJqWEM5bE5HUkxaMHg0U0hCSWRIRnNZM1JhVTFoTlVITkxhVXBDVlhGclBTSXNJbWxrWlc1MGFYUjVJam9pT0dVeFlUZzFZVEEwWVRKbFpqWXlZV016T1RCa05qSmhZVGxqTkRjNE5EaG1OV0l3WXpjMFkyVmxPV0ptT0RZM01XUTVNamxqWXpVNE5UUmxNR0UwWVNJc0ltbGtaVzUwYVhSNVgzUjVjR1VpT2lKcFpHVnVkR2wwZVY5allYSmtYMmxrSWl3aWMyTnZjR1VpT2lKaGNIQnNhV05oZEdsdmJpSXNJbWx1Wm04aU9uc2laR1YyYVdObFgyNWhiV1VpT2lKUGJHVnJjMkZ1WkhMaWdKbHpJRTFoWTBKdmIyc2dVSEp2SWl3aVpHVjJhV05sSWpvaWFWQm9iMjVsSW4xOSIsImlkIjoiMzBmYmVhZWUzZDgyZjM0NjA5NmZhOTliZTAxMzlmNmRiM2U0NzIxZjViNWM5ZWVlNTE0NmUwYTM0ODk4ODVkOSJ9");
		CardModel otCard = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5paGVLTllNR2hKTnMzYzA1ekhuVTBHXC9BMldwY1JqNjNsSm0rVnE5a0lUZXNuSnFrSG04QUM4VW9uc1RZQjJBeHVVYVJaRGNvSjlNenJ2a2o5d0hBbz0iLCI0ZjNlYzNjYmUxMWUxNGJjZmJiNjI2NWFiZjAzYzRhMjFkNjA5OGQ0YWVkYmMwNmZiNjY4YzJmNjJjYzkzZWY4IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5nUGJ3b01DMnRkZkwwXC9hVHZpRmQ3aExiODhoWjVWY1V3Znk2QW9cL09Jamtxc2JySnZ0Tk9EVlRmYnFxQ1BxNXJpaXpsSloxUWxMZCtBQmFQZTFIZzQ9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXcGxVbVpsTjJreGVUUlpVR3B5UkRkMWMzY3lTek5TYTFGRFJpdE9WMnQxTTBWV05sQnBPSHB1WTFrOUlpd2lhV1JsYm5ScGRIa2lPaUk0WlRGaE9EVmhNRFJoTW1WbU5qSmhZek01TUdRMk1tRmhPV00wTnpnME9HWTFZakJqTnpSalpXVTVZbVk0TmpjeFpEa3lPV05qTlRnMU5HVXdZVFJoSWl3aWFXUmxiblJwZEhsZmRIbHdaU0k2SW1sa1pXNTBhWFI1WDJOaGNtUmZhV1FpTENKelkyOXdaU0k2SW1Gd2NHeHBZMkYwYVc5dUlpd2lhVzVtYnlJNmV5SmtaWFpwWTJWZmJtRnRaU0k2SWs5c1pXdHpZVzVrY3VLQW1YTWdUV0ZqUW05dmF5QlFjbThpTENKa1pYWnBZMlVpT2lKcFVHaHZibVVpZlgwPSIsImlkIjoiZDBhZWQzNjdhN2M0ZmE4ZWRhZDBkNjE3ZmU2MDAxNjNjNDMzMTZmOTI5ZTRhMDFlZjExMTBkOTkxYmM0MDA2ZSJ9");

		RecipientCardsSet recipientCardsSet = new RecipientCardsSet(ltCard, otCard);

		SecureSession session = this.sessionManager.initializeInitiatorSession(this.card, recipientCardsSet, null);

		this.keyStorageManager.getSessionKeys(session.getIdentifier());

		assertTrue(session.getAdditionalData().length > 0);
		assertTrue(session.getDecryptionKey().length > 0);
		assertTrue(session.getEncryptionKey().length > 0);

		Calendar cal = Calendar.getInstance();
		Date now = cal.getTime();

		cal.add(Calendar.SECOND, this.sessionTtl);
		Date expUpperBound = cal.getTime();

		cal.add(Calendar.MILLISECOND, -500);
		Date expLowerBound = cal.getTime();

		assertTrue(session.getExpirationDate().after(expLowerBound));
		assertTrue(session.getExpirationDate().before(expUpperBound));
		assertFalse(session.isExpired(now));
		assertTrue(session.getIdentifier().length > 0);

		SecureSession activeSession = this.sessionManager.activeSession(this.card.getId());
		assertNotNull(activeSession);
		assertThat(activeSession, is(session));

		SecureSession loadedSession = this.sessionManager.loadSession(this.card.getId(), session.getIdentifier());
		assertNotNull(loadedSession);
		assertThat(loadedSession, is(session));
		;

		this.sessionManager.removeSessions(this.card.getId());
		assertNull(this.sessionManager.activeSession(this.card.getId()));

		try {
			this.sessionManager.loadSession(this.card.getId(), session.getIdentifier());
			fail();
		} catch (SessionManagerException e) {
			assertEquals(Constants.Errors.SessionManager.SESSION_NOT_FOUND, e.getCode());
		}
	}

	@Test
	public void initializeResponder() throws SessionManagerException {
		String cardId = TestUtils.generateCardId();
		String otKeyName = TestUtils.generateKeyName();
		SecureSession session = this.generateResponderSession(cardId, otKeyName);

		try {
			this.keyStorageManager.getOtPrivateKey(otKeyName);
			fail();
		} catch (Exception e) {
		}

		this.keyStorageManager.getSessionKeys(session.getIdentifier());

		assertTrue(session.getAdditionalData().length > 0);
		assertTrue(session.getDecryptionKey().length > 0);
		assertTrue(session.getEncryptionKey().length > 0);

		Calendar cal = Calendar.getInstance();
		Date now = cal.getTime();

		cal.add(Calendar.SECOND, this.sessionTtl);
		Date expUpperBound = cal.getTime();

		cal.add(Calendar.MILLISECOND, -500);
		Date expLowerBound = cal.getTime();

		assertTrue(session.getExpirationDate().after(expLowerBound));
		assertTrue(session.getExpirationDate().before(expUpperBound));
		assertFalse(session.isExpired(now));
		assertTrue(session.getIdentifier().length > 0);

		SecureSession activeSession = this.sessionManager.activeSession(cardId);
		assertNotNull(activeSession);
		assertThat(activeSession, is(session));

		SecureSession loadedSession = this.sessionManager.loadSession(cardId, session.getIdentifier());
		assertNotNull(loadedSession);
		assertThat(loadedSession, is(session));

		this.sessionManager.removeSessions(cardId);
		assertNull(this.sessionManager.activeSession(cardId));

		try {
			this.sessionManager.loadSession(cardId, session.getIdentifier());
			fail();
		} catch (SessionManagerException e) {
		}
	}

	@Test
	public void activeSessionChange() throws SessionManagerException, InterruptedException {
		String cardId = TestUtils.generateCardId();

		SecureSession session1 = this.generateResponderSession(cardId, TestUtils.generateKeyName());
		SecureSession session2 = this.generateResponderSession(cardId, TestUtils.generateKeyName());
		SecureSession session3 = this.generateResponderSession(cardId, TestUtils.generateKeyName());

		this.keyStorageManager.getSessionKeys(session1.getIdentifier());
		this.keyStorageManager.getSessionKeys(session2.getIdentifier());
		this.keyStorageManager.getSessionKeys(session3.getIdentifier());

		SecureSession activeSession = this.sessionManager.activeSession(cardId);
		assertNotNull(activeSession);
		assertThat(activeSession, not(is(session1)));
		assertThat(activeSession, is(session3));

		SecureSession loadedSession1 = this.sessionManager.loadSession(cardId, session1.getIdentifier());
		SecureSession loadedSession2 = this.sessionManager.loadSession(cardId, session2.getIdentifier());
		SecureSession loadedSession3 = this.sessionManager.loadSession(cardId, session3.getIdentifier());

		assertThat(loadedSession1, is(session1));
		assertThat(loadedSession2, is(session2));
		assertThat(loadedSession3, is(session3));

		this.sessionManager.removeSession(cardId, session3.getIdentifier());

		SecureSession loadedSession21 = this.sessionManager.loadSession(cardId, session1.getIdentifier());
		SecureSession loadedSession22 = this.sessionManager.loadSession(cardId, session2.getIdentifier());

		assertThat(loadedSession21, is(session1));
		assertThat(loadedSession22, is(session2));

		try {
			this.sessionManager.loadSession(cardId, session3.getIdentifier());
			fail();
		} catch (SessionManagerException e) {
		}

		SecureSession activeSession2 = this.sessionManager.activeSession(cardId);
		assertThat(activeSession2, is(session2));
	}

	@Test
	public void gentleReset() throws SessionManagerException {
		String cardId1 = TestUtils.generateCardId();
		String cardId2 = TestUtils.generateCardId();

		SecureSession session11 = this.generateResponderSession(cardId1, TestUtils.generateKeyName());
		SecureSession session12 = this.generateResponderSession(cardId1, TestUtils.generateKeyName());
		SecureSession session21 = this.generateResponderSession(cardId2, TestUtils.generateKeyName());

		this.keyStorageManager.getSessionKeys(session11.getIdentifier());
		this.keyStorageManager.getSessionKeys(session12.getIdentifier());
		this.keyStorageManager.getSessionKeys(session21.getIdentifier());

		this.sessionManager.gentleReset();

		assertNull(this.sessionManager.activeSession(cardId1));
		assertNull(this.sessionManager.activeSession(cardId2));

		try {
			this.sessionManager.loadSession(cardId1, session11.getIdentifier());
			fail();
		} catch (SessionManagerException e) {
		}

		try {
			this.sessionManager.loadSession(cardId1, session12.getIdentifier());
			fail();
		} catch (SessionManagerException e) {
		}

		try {
			this.sessionManager.loadSession(cardId2, session21.getIdentifier());
			fail();
		} catch (SessionManagerException e) {
		}

		try {
			this.keyStorageManager.getSessionKeys(session11.getIdentifier());
			fail();
		} catch (Exception e) {
		}

		try {
			this.keyStorageManager.getSessionKeys(session12.getIdentifier());
			fail();
		} catch (Exception e) {
		}

		try {
			this.keyStorageManager.getSessionKeys(session21.getIdentifier());
			fail();
		} catch (Exception e) {
		}
	}

	@Test
	public void initializeResponderInvalidEphKeySignature() {
		String cardId = TestUtils.generateCardId();
		String otKeyName = TestUtils.generateKeyName();
		PrivateKey privateKey = this.crypto.generateKeys().getPrivateKey();
		CardEntry idEntry = new CardEntry(cardId,
				this.crypto.exportPublicKey(this.crypto.extractPublicKey(privateKey)));

		String ltKeyName = TestUtils.generateKeyName();

		this.keyStorageManager.saveKeys(
				Arrays.asList(
						new KeyStorageManager.HelperKeyEntry(this.crypto.generateKeys().getPrivateKey(), otKeyName)),
				new KeyStorageManager.HelperKeyEntry(this.crypto.generateKeys().getPrivateKey(), ltKeyName));

		byte[] ephPublicKeyData = this.crypto.exportPublicKey(this.crypto.generateKeys().getPublicKey());
		byte[] ephPublicKeySignature = this.crypto.sign(ephPublicKeyData, this.crypto.generateKeys().getPrivateKey());

		byte[] cipherText = TestUtils.generateBytes(16);
		byte[] salt = TestUtils.generateBytes(16);

		InitiationMessage initiationMessage = new InitiationMessage(idEntry.getIdentifier(), TestUtils.generateCardId(),
				ltKeyName, otKeyName, ephPublicKeyData, ephPublicKeySignature, salt, cipherText);

		try {
			this.sessionManager.initializeResponderSession(idEntry, initiationMessage, null);
			fail();
		} catch (SessionManagerException e) {
		}
	}

	@Test(expected = SessionManagerException.class)
	public void initializeInitiatorWrongOtCardSignature() throws SessionManagerException {
		CardModel ltCard = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU1jZWhpXC9ZVXFvZlpVbGdJVmdaRjgzc2ZcL2tObzNNZ0wzQlRmNDVlMWx0eWp1RkhBbWEzMGpCWVBEVDVuY1piQ0gxVXNmekJwbU9US1ZKb2laMXV4ZzQ9IiwiNGYzZWMzY2JlMTFlMTRiY2ZiYjYyNjVhYmYwM2M0YTIxZDYwOThkNGFlZGJjMDZmYjY2OGMyZjYyY2M5M2VmOCI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFEeFJPWFFCV2ZxWjVYdnhlOWRtUlwvWk40akgrNm90eENxWWY3aFcrcDRaN2VVSFhuUytIbDR4MkZibmtFc2xPZDZ0SHRWTGsrRWNvZnBUUWxPNFRad2s9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFUVktOMU00VEhCS1pETnZTbEJqWEM5bE5HUkxaMHg0U0hCSWRIRnNZM1JhVTFoTlVITkxhVXBDVlhGclBTSXNJbWxrWlc1MGFYUjVJam9pT0dVeFlUZzFZVEEwWVRKbFpqWXlZV016T1RCa05qSmhZVGxqTkRjNE5EaG1OV0l3WXpjMFkyVmxPV0ptT0RZM01XUTVNamxqWXpVNE5UUmxNR0UwWVNJc0ltbGtaVzUwYVhSNVgzUjVjR1VpT2lKcFpHVnVkR2wwZVY5allYSmtYMmxrSWl3aWMyTnZjR1VpT2lKaGNIQnNhV05oZEdsdmJpSXNJbWx1Wm04aU9uc2laR1YyYVdObFgyNWhiV1VpT2lKUGJHVnJjMkZ1WkhMaWdKbHpJRTFoWTBKdmIyc2dVSEp2SWl3aVpHVjJhV05sSWpvaWFWQm9iMjVsSW4xOSIsImlkIjoiMzBmYmVhZWUzZDgyZjM0NjA5NmZhOTliZTAxMzlmNmRiM2U0NzIxZjViNWM5ZWVlNTE0NmUwYTM0ODk4ODVkOSJ9");
		CardModel otCard = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUJwVmlWYmhRRDhKbVZUT1JndGsrWHM0ajVqSG13RW1uM1RpL1ZPUC9YWU80WDRFdlpneTlyVWFxZ0trYm8xb1RBUUcvaTBsNHpjM1dyN3QzRUM5OUE0PSIsIjRmM2VjM2NiZTExZTE0YmNmYmI2MjY1YWJmMDNjNGEyMWQ2MDk4ZDRhZWRiYzA2ZmI2NjhjMmY2MmNjOTNlZjgiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRTmdQYndvTUMydGRmTDBcL2FUdmlGZDdoTGI4OGhaNVZjVXdmeTZBb1wvT0lqa3FzYnJKdnROT0RWVGZicXFDUHE1cmlpemxKWjFRbExkK0FCYVBlMUhnND0ifX0sImNvbnRlbnRfc25hcHNob3QiOiJleUp3ZFdKc2FXTmZhMlY1SWpvaVRVTnZkMEpSV1VSTE1sWjNRWGxGUVdwbFVtWmxOMmt4ZVRSWlVHcHlSRGQxYzNjeVN6TlNhMUZEUml0T1YydDFNMFZXTmxCcE9IcHVZMWs5SWl3aWFXUmxiblJwZEhraU9pSTRaVEZoT0RWaE1EUmhNbVZtTmpKaFl6TTVNR1EyTW1GaE9XTTBOemcwT0dZMVlqQmpOelJqWldVNVltWTROamN4WkRreU9XTmpOVGcxTkdVd1lUUmhJaXdpYVdSbGJuUnBkSGxmZEhsd1pTSTZJbWxrWlc1MGFYUjVYMk5oY21SZmFXUWlMQ0p6WTI5d1pTSTZJbUZ3Y0d4cFkyRjBhVzl1SWl3aWFXNW1ieUk2ZXlKa1pYWnBZMlZmYm1GdFpTSTZJazlzWld0ellXNWtjdUtBbVhNZ1RXRmpRbTl2YXlCUWNtOGlMQ0prWlhacFkyVWlPaUpwVUdodmJtVWlmWDA9IiwiaWQiOiJkMGFlZDM2N2E3YzRmYThlZGFkMGQ2MTdmZTYwMDE2M2M0MzMxNmY5MjllNGEwMWVmMTExMGQ5OTFiYzQwMDZlIn0=");

		RecipientCardsSet recipientCardsSet = new RecipientCardsSet(ltCard, otCard);

		this.sessionManager.initializeInitiatorSession(this.card, recipientCardsSet, null);
	}

	@Test(expected = SessionManagerException.class)
	public void initializeInitiatorWrongLtCardSignature() throws SessionManagerException {
		CardModel ltCard = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUt5WS9wTnVWNkNacXhOd3NQQ0kzT0J6SXlCYld5TmpTWENVUDdpM2ltT1hhbXF2aGxLb2xUMW8vMm8xODIxYlE1TXlFeW5uSHVCVWMvWERQVk1IV2dBPSIsIjRmM2VjM2NiZTExZTE0YmNmYmI2MjY1YWJmMDNjNGEyMWQ2MDk4ZDRhZWRiYzA2ZmI2NjhjMmY2MmNjOTNlZjgiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRRHhST1hRQldmcVo1WHZ4ZTlkbVJcL1pONGpIKzZvdHhDcVlmN2hXK3A0WjdlVUhYblMrSGw0eDJGYm5rRXNsT2Q2dEh0VkxrK0Vjb2ZwVFFsTzRUWndrPSJ9fSwiY29udGVudF9zbmFwc2hvdCI6ImV5SndkV0pzYVdOZmEyVjVJam9pVFVOdmQwSlJXVVJMTWxaM1FYbEZRVFZLTjFNNFRIQktaRE52U2xCalhDOWxOR1JMWjB4NFNIQklkSEZzWTNSYVUxaE5VSE5MYVVwQ1ZYRnJQU0lzSW1sa1pXNTBhWFI1SWpvaU9HVXhZVGcxWVRBMFlUSmxaall5WVdNek9UQmtOakpoWVRsak5EYzRORGhtTldJd1l6YzBZMlZsT1dKbU9EWTNNV1E1TWpsall6VTROVFJsTUdFMFlTSXNJbWxrWlc1MGFYUjVYM1I1Y0dVaU9pSnBaR1Z1ZEdsMGVWOWpZWEprWDJsa0lpd2ljMk52Y0dVaU9pSmhjSEJzYVdOaGRHbHZiaUlzSW1sdVptOGlPbnNpWkdWMmFXTmxYMjVoYldVaU9pSlBiR1ZyYzJGdVpITGlnSmx6SUUxaFkwSnZiMnNnVUhKdklpd2laR1YyYVdObElqb2lhVkJvYjI1bEluMTkiLCJpZCI6IjMwZmJlYWVlM2Q4MmYzNDYwOTZmYTk5YmUwMTM5ZjZkYjNlNDcyMWY1YjVjOWVlZTUxNDZlMGEzNDg5ODg1ZDkifQ==");
		CardModel otCard = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5paGVLTllNR2hKTnMzYzA1ekhuVTBHXC9BMldwY1JqNjNsSm0rVnE5a0lUZXNuSnFrSG04QUM4VW9uc1RZQjJBeHVVYVJaRGNvSjlNenJ2a2o5d0hBbz0iLCI0ZjNlYzNjYmUxMWUxNGJjZmJiNjI2NWFiZjAzYzRhMjFkNjA5OGQ0YWVkYmMwNmZiNjY4YzJmNjJjYzkzZWY4IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5nUGJ3b01DMnRkZkwwXC9hVHZpRmQ3aExiODhoWjVWY1V3Znk2QW9cL09Jamtxc2JySnZ0Tk9EVlRmYnFxQ1BxNXJpaXpsSloxUWxMZCtBQmFQZTFIZzQ9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXcGxVbVpsTjJreGVUUlpVR3B5UkRkMWMzY3lTek5TYTFGRFJpdE9WMnQxTTBWV05sQnBPSHB1WTFrOUlpd2lhV1JsYm5ScGRIa2lPaUk0WlRGaE9EVmhNRFJoTW1WbU5qSmhZek01TUdRMk1tRmhPV00wTnpnME9HWTFZakJqTnpSalpXVTVZbVk0TmpjeFpEa3lPV05qTlRnMU5HVXdZVFJoSWl3aWFXUmxiblJwZEhsZmRIbHdaU0k2SW1sa1pXNTBhWFI1WDJOaGNtUmZhV1FpTENKelkyOXdaU0k2SW1Gd2NHeHBZMkYwYVc5dUlpd2lhVzVtYnlJNmV5SmtaWFpwWTJWZmJtRnRaU0k2SWs5c1pXdHpZVzVrY3VLQW1YTWdUV0ZqUW05dmF5QlFjbThpTENKa1pYWnBZMlVpT2lKcFVHaHZibVVpZlgwPSIsImlkIjoiZDBhZWQzNjdhN2M0ZmE4ZWRhZDBkNjE3ZmU2MDAxNjNjNDMzMTZmOTI5ZTRhMDFlZjExMTBkOTkxYmM0MDA2ZSJ9");

		RecipientCardsSet recipientCardsSet = new RecipientCardsSet(ltCard, otCard);

		this.sessionManager.initializeInitiatorSession(this.card, recipientCardsSet, null);
	}

	private SecureSession generateResponderSession(String cardId, String otKeyName) throws SessionManagerException {
		PrivateKey privateKey = this.crypto.generateKeys().getPrivateKey();
		CardEntry idEntry = new CardEntry(cardId,
				this.crypto.exportPublicKey(this.crypto.extractPublicKey(privateKey)));

		String ltKeyName = UUID.randomUUID().toString();

		this.keyStorageManager.saveKeys(
				Arrays.asList(
						new KeyStorageManager.HelperKeyEntry(this.crypto.generateKeys().getPrivateKey(), otKeyName)),
				new KeyStorageManager.HelperKeyEntry(this.crypto.generateKeys().getPrivateKey(), ltKeyName));

		byte[] ephPublicKeyData = this.crypto.exportPublicKey(this.crypto.generateKeys().getPublicKey());
		byte[] ephPublicKeySignature = this.crypto.sign(ephPublicKeyData, privateKey);

		byte[] cipherText = TestUtils.generateBytes(16);
		byte[] salt = TestUtils.generateBytes(16);

		InitiationMessage initiationMessage = new InitiationMessage(idEntry.getIdentifier(),
				UUID.randomUUID().toString(), ltKeyName, otKeyName, ephPublicKeyData, ephPublicKeySignature, salt,
				cipherText);

		SecureSession session = this.sessionManager.initializeResponderSession(idEntry, initiationMessage, null);

		return session;
	}

}
