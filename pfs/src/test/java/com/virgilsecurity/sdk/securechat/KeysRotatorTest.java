package com.virgilsecurity.sdk.securechat;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.VirgilClient;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.pfs.BaseIT;
import com.virgilsecurity.sdk.pfs.VirgilPFSClient;
import com.virgilsecurity.sdk.pfs.VirgilPFSClientContext;
import com.virgilsecurity.sdk.pfs.model.RecipientCardsSet;
import com.virgilsecurity.sdk.pfs.model.response.OtcCountResponse;
import com.virgilsecurity.sdk.securechat.exceptions.SessionManagerException;
import com.virgilsecurity.sdk.securechat.impl.DefaultUserDataStorage;
import com.virgilsecurity.sdk.securechat.keystorage.JsonFileKeyStorage;
import com.virgilsecurity.sdk.securechat.keystorage.KeyAttrs;
import com.virgilsecurity.sdk.securechat.keystorage.KeyStorage;
import com.virgilsecurity.sdk.securechat.session.SecureSession;
import com.virgilsecurity.sdk.securechat.session.SessionInitializer;
import com.virgilsecurity.sdk.securechat.session.SessionManager;

public class KeysRotatorTest extends BaseIT {
	private KeysRotator keysRotator;
	private VirgilClient virgilClient;
	private VirgilPFSClient pfsClient;
	private UserDataStorage storage;
	private KeyStorage keyStorage;
	private KeyStorageManager keyStorageManager;
	private SessionStorageManager sessionStorageManager;
	private SessionManager sessionManager;
	private CardModel card, ltCard, otCard;

	@Before
	public void setUp() throws MalformedURLException, CryptoException {
		// Initialize Crypto
		crypto = new VirgilCrypto();

		// Prepare context
		VirgilPFSClientContext ctx = new VirgilPFSClientContext(APP_TOKEN);

		String url = getPropertyByName("CARDS_SERVICE");
		if (StringUtils.isNotBlank(url)) {
			ctx.setCardsServiceURL(new URL(url));
		}
		url = getPropertyByName("RO_CARDS_SERVICE");
		if (StringUtils.isNotBlank(url)) {
			ctx.setReadOnlyCardsServiceURL(new URL(url));
		}
		url = getPropertyByName("IDENTITY_SERVICE");
		if (StringUtils.isNotBlank(url)) {
			ctx.setIdentityServiceURL(new URL(url));
		}
		url = getPropertyByName("EPH_SERVICE");
		if (StringUtils.isNotBlank(url)) {
			ctx.setEphemeralServiceURL(new URL(url));
		}

		appKey = crypto.importPrivateKey(APP_PRIVATE_KEY.getBytes(), APP_PRIVATE_KEY_PASSWORD);

		virgilClient = new VirgilClient(ctx);
		pfsClient = new VirgilPFSClient(ctx);

		this.card = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI3KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUdYWEpDVFdpc25cL1VReUNjM0o3WUk3a1QwcEJzUlJqWFZweVlzcDN3aGRtN0p3YlljN2RTVkdSWXdtaEtWODBjSGVKVUw4S0JvNENzT2Uzb3p5RGhRaz0iLCJhNjY2MzE4MDcxMjc0YWRiNzM4YWYzZjY3YjhjN2VjMjlkOTU0ZGUyY2FiZmQ3MWE5NDJlNmVhMzhlNTlmZmY5IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUURzS3pDQ3Jxb1hlY3Q4V3psVGphRlVXTWkyeEtJYkxKa0Fnd3AyTnBnd3RuYVpoYURsSllMbGh4WDlma25EQTNSRW5nSzBYSExRaG40Zzkxa3NKSmdZPSIsImU2ODBiZWY4N2JhNzVkMzMxYjBhMDJiZmE2YTIwZjAyZWI1YzViYTliYzk2ZmM2MWNhNTk1NDA0YjEwMDI2ZjQiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRRXlobUxHOURiTHBWa3k3c2ttUTVBRTN4T21lMVlpVUpWNjFlemRSZ04rTGlwSmJrclwvclB1VXo3eFJERmUzY294TGM2elRFbUZlK1BqV1BMTnVFcGdrPSJ9fSwiY29udGVudF9zbmFwc2hvdCI6ImV5SndkV0pzYVdOZmEyVjVJam9pVFVOdmQwSlJXVVJMTWxaM1FYbEZRVlZaVTNkQk5XZE9iR2RUVXpSMVQwSlFibmRLVDNOQmFsVkJSSEk1V2xwbFdGWjROakp2YTB0V2RFMDlJaXdpYVdSbGJuUnBkSGtpT2lKQ1JqbEdORFZHUVMwMU9EbEZMVFF6TlRBdE9FVkNRUzAyUWtaRlFVTkNOa05GUTBVaUxDSnBaR1Z1ZEdsMGVWOTBlWEJsSWpvaWRHVnpkQ0lzSW5OamIzQmxJam9pWVhCd2JHbGpZWFJwYjI0aWZRPT0iLCJpZCI6IjhlMWE4NWEwNGEyZWY2MmFjMzkwZDYyYWE5YzQ3ODQ4ZjViMGM3NGNlZTliZjg2NzFkOTI5Y2M1ODU0ZTBhNGEifQ==");
		this.ltCard = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU1jZWhpXC9ZVXFvZlpVbGdJVmdaRjgzc2ZcL2tObzNNZ0wzQlRmNDVlMWx0eWp1RkhBbWEzMGpCWVBEVDVuY1piQ0gxVXNmekJwbU9US1ZKb2laMXV4ZzQ9IiwiNGYzZWMzY2JlMTFlMTRiY2ZiYjYyNjVhYmYwM2M0YTIxZDYwOThkNGFlZGJjMDZmYjY2OGMyZjYyY2M5M2VmOCI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFEeFJPWFFCV2ZxWjVYdnhlOWRtUlwvWk40akgrNm90eENxWWY3aFcrcDRaN2VVSFhuUytIbDR4MkZibmtFc2xPZDZ0SHRWTGsrRWNvZnBUUWxPNFRad2s9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFUVktOMU00VEhCS1pETnZTbEJqWEM5bE5HUkxaMHg0U0hCSWRIRnNZM1JhVTFoTlVITkxhVXBDVlhGclBTSXNJbWxrWlc1MGFYUjVJam9pT0dVeFlUZzFZVEEwWVRKbFpqWXlZV016T1RCa05qSmhZVGxqTkRjNE5EaG1OV0l3WXpjMFkyVmxPV0ptT0RZM01XUTVNamxqWXpVNE5UUmxNR0UwWVNJc0ltbGtaVzUwYVhSNVgzUjVjR1VpT2lKcFpHVnVkR2wwZVY5allYSmtYMmxrSWl3aWMyTnZjR1VpT2lKaGNIQnNhV05oZEdsdmJpSXNJbWx1Wm04aU9uc2laR1YyYVdObFgyNWhiV1VpT2lKUGJHVnJjMkZ1WkhMaWdKbHpJRTFoWTBKdmIyc2dVSEp2SWl3aVpHVjJhV05sSWpvaWFWQm9iMjVsSW4xOSIsImlkIjoiMzBmYmVhZWUzZDgyZjM0NjA5NmZhOTliZTAxMzlmNmRiM2U0NzIxZjViNWM5ZWVlNTE0NmUwYTM0ODk4ODVkOSJ9");
		this.otCard = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5paGVLTllNR2hKTnMzYzA1ekhuVTBHXC9BMldwY1JqNjNsSm0rVnE5a0lUZXNuSnFrSG04QUM4VW9uc1RZQjJBeHVVYVJaRGNvSjlNenJ2a2o5d0hBbz0iLCI0ZjNlYzNjYmUxMWUxNGJjZmJiNjI2NWFiZjAzYzRhMjFkNjA5OGQ0YWVkYmMwNmZiNjY4YzJmNjJjYzkzZWY4IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5nUGJ3b01DMnRkZkwwXC9hVHZpRmQ3aExiODhoWjVWY1V3Znk2QW9cL09Jamtxc2JySnZ0Tk9EVlRmYnFxQ1BxNXJpaXpsSloxUWxMZCtBQmFQZTFIZzQ9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXcGxVbVpsTjJreGVUUlpVR3B5UkRkMWMzY3lTek5TYTFGRFJpdE9WMnQxTTBWV05sQnBPSHB1WTFrOUlpd2lhV1JsYm5ScGRIa2lPaUk0WlRGaE9EVmhNRFJoTW1WbU5qSmhZek01TUdRMk1tRmhPV00wTnpnME9HWTFZakJqTnpSalpXVTVZbVk0TmpjeFpEa3lPV05qTlRnMU5HVXdZVFJoSWl3aWFXUmxiblJwZEhsZmRIbHdaU0k2SW1sa1pXNTBhWFI1WDJOaGNtUmZhV1FpTENKelkyOXdaU0k2SW1Gd2NHeHBZMkYwYVc5dUlpd2lhVzVtYnlJNmV5SmtaWFpwWTJWZmJtRnRaU0k2SWs5c1pXdHpZVzVrY3VLQW1YTWdUV0ZqUW05dmF5QlFjbThpTENKa1pYWnBZMlVpT2lKcFVHaHZibVVpZlgwPSIsImlkIjoiZDBhZWQzNjdhN2M0ZmE4ZWRhZDBkNjE3ZmU2MDAxNjNjNDMzMTZmOTI5ZTRhMDFlZjExMTBkOTkxYmM0MDA2ZSJ9");

		storage = new DefaultUserDataStorage();
		keyStorage = new JsonFileKeyStorage(System.getProperty("java.io.tmpdir"), UUID.randomUUID().toString());
	}

	@Test
	public void rotateKeys() {
		KeyPair keyPair = this.crypto.generateKeys();

		PublishCardRequest identityRequest = instantiateCreateCardRequest(keyPair);

		CardModel card = this.virgilClient.publishCard(identityRequest);
		this.initializeRotator(keyPair.getPrivateKey(), card, 100, 100, 100, 100);
		this.keysRotator.rotateKeys(10);
	}

	@Test
	public void simultaneousCalls() throws InterruptedException, ExecutionException {
		KeyPair keyPair = this.crypto.generateKeys();

		PublishCardRequest identityRequest = instantiateCreateCardRequest(keyPair);

		CardModel card = this.virgilClient.publishCard(identityRequest);

		this.initializeRotator(keyPair.getPrivateKey(), card, 100, 100, 100, 100);

		FutureTask<Void> f1 = new FutureTask<Void>(new Callable<Void>() {
			public Void call() {
				keysRotator.rotateKeys(30);
				return null;
			}
		});
		FutureTask<Void> f2 = new FutureTask<Void>(new Callable<Void>() {
			public Void call() {
				keysRotator.rotateKeys(10);
				return null;
			}
		});
		ExecutorService executor = Executors.newFixedThreadPool(2);
		executor.execute(f1);
		executor.execute(f2);

		f1.get();
		f2.get();
	}

	@Test
	public void otcRotation() {
		KeyPair keyPair = this.crypto.generateKeys();

		PublishCardRequest identityRequest = instantiateCreateCardRequest(keyPair);

		CardModel card = this.virgilClient.publishCard(identityRequest);
		this.initializeRotator(keyPair.getPrivateKey(), card, 100, 100, 100, 100);

		String cardId = card.getId();

		this.keysRotator.rotateKeys(10);
		OtcCountResponse status = this.pfsClient.getOtcCount(cardId);
		assertEquals(10, status.getActive());

		this.keysRotator.rotateKeys(10);
		status = this.pfsClient.getOtcCount(cardId);
		assertEquals(10, status.getActive());

		this.keysRotator.rotateKeys(100);
		status = this.pfsClient.getOtcCount(cardId);
		assertEquals(100, status.getActive());
	}

	@Test
	public void removeOrhpanedOtc() throws InterruptedException, CryptoException {
		int exhaustTime = 10;

		KeyPair keyPair = this.crypto.generateKeys();

		PublishCardRequest identityRequest = instantiateCreateCardRequest(keyPair);

		CardModel card = this.virgilClient.publishCard(identityRequest);
		this.initializeRotator(keyPair.getPrivateKey(), card, exhaustTime, 100, 100, 100);

		String cardId = card.getId();

		this.keysRotator.rotateKeys(10);

		Map<String, List<KeyAttrs>> keyAttrs = this.keyStorageManager.getAllKeysAttrs();
		assertEquals(10, keyAttrs.get(KeyStorageManager.OT_KEYS).size());

		List<RecipientCardsSet> cardsSets = this.pfsClient.getRecipientCardsSet(cardId);
		assertEquals(1, cardsSets.size());

		RecipientCardsSet cardsSet = cardsSets.get(0);

		String ltId = cardsSet.getLongTermCard().getId();
		String otId = null;
		if (cardsSet.getOneTimeCard() != null) {
			otId = cardsSet.getOneTimeCard().getId();
		}

		this.keyStorageManager.getOtPrivateKey(otId);
		this.keyStorageManager.getLtPrivateKey(ltId);

		this.keysRotator.rotateKeys(10);

		this.keyStorageManager.getOtPrivateKey(otId);

		this.keysRotator.rotateKeys(10);
		this.keyStorageManager.getOtPrivateKey(otId);

		Thread.sleep(exhaustTime * 1000);

		this.keysRotator.rotateKeys(10);

		try {
			this.keyStorageManager.getOtPrivateKey(otId);
			fail();
		} catch (KeyEntryNotFoundException e) {
		}

		OtcCountResponse status = this.pfsClient.getOtcCount(cardId);

		assertEquals(10, status.getActive());
	}

	@Test
	public void ltcRotation() throws CryptoException, InterruptedException {
		int expireTime = 10;
		int exhaustTime = 10;

		KeyPair keyPair = this.crypto.generateKeys();

		PublishCardRequest identityRequest = instantiateCreateCardRequest(keyPair);

		CardModel card = this.virgilClient.publishCard(identityRequest);
		this.initializeRotator(keyPair.getPrivateKey(), card, 100, 100, expireTime, exhaustTime);

		String cardId = card.getId();

		this.keysRotator.rotateKeys(0);

		Map<String, List<KeyAttrs>> keyAttrs = this.keyStorageManager.getAllKeysAttrs();
		assertEquals(1, keyAttrs.get(KeyStorageManager.LT_KEYS).size());
		assertEquals(0, keyAttrs.get(KeyStorageManager.OT_KEYS).size());

		List<RecipientCardsSet> cardsSets = this.pfsClient.getRecipientCardsSet(cardId);
		assertEquals(1, cardsSets.size());

		RecipientCardsSet cardsSet = cardsSets.get(0);
		assertNull(cardsSet.getOneTimeCard());

		String ltId = cardsSet.getLongTermCard().getId();

		this.keyStorageManager.getLtPrivateKey(ltId);

		this.keysRotator.rotateKeys(0);
		this.keyStorageManager.getLtPrivateKey(ltId);

		Thread.sleep(expireTime * 1000);

		this.keysRotator.rotateKeys(0);

		this.keyStorageManager.getLtPrivateKey(ltId);

		Thread.sleep(exhaustTime * 1000);

		this.keysRotator.rotateKeys(0);

		try {
			this.keyStorageManager.getLtPrivateKey(ltId);
		} catch (KeyEntryNotFoundException e) {
		}
	}

	@Test
	public void sessionsLifecycle() throws InterruptedException, SessionManagerException {
		int expireTime = 10;
		int exhaustTime = 10;

		KeyPair keyPair = this.crypto.generateKeys();

		PublishCardRequest identityRequest = instantiateCreateCardRequest(keyPair);

		CardModel card = this.virgilClient.publishCard(identityRequest);
		this.initializeRotator(keyPair.getPrivateKey(), card, 100, exhaustTime, 100, 100);
		this.initializeSessionManager(card, expireTime);

		this.keysRotator.rotateKeys(0);

		Map<String, List<KeyAttrs>> keyAttrs = this.keyStorageManager.getAllKeysAttrs();
		assertEquals(0, keyAttrs.get(KeyStorageManager.SESSION_KEYS).size());
		// assertEquals(0,
		// this.sessionStorageManager.getAllSessionsStates().size());

		RecipientCardsSet cardsSet = new RecipientCardsSet(this.ltCard, this.otCard);
		SecureSession session = this.sessionManager.initializeInitiatorSession(this.card, cardsSet, null);
		byte[] sessionId = session.getIdentifier();

		keyAttrs = this.keyStorageManager.getAllKeysAttrs();
		assertEquals(1, keyAttrs.get(KeyStorageManager.SESSION_KEYS).size());
		assertEquals(1, this.sessionStorageManager.getAllSessionsStates().size());

		this.keyStorageManager.getSessionKeys(sessionId);
		assertNotNull(this.sessionStorageManager.getSessionState(this.card.getId(), sessionId));

		this.keysRotator.rotateKeys(0);
		this.keyStorageManager.getSessionKeys(sessionId);
		assertNotNull(this.sessionStorageManager.getSessionState(this.card.getId(), sessionId));

		Thread.sleep(expireTime * 1000);

		this.keysRotator.rotateKeys(0);
		this.keyStorageManager.getSessionKeys(sessionId);
		assertNotNull(this.sessionStorageManager.getSessionState(this.card.getId(), sessionId));

		Thread.sleep(exhaustTime * 1000);

		this.keysRotator.rotateKeys(0);
		try {
			this.keyStorageManager.getSessionKeys(sessionId);
			fail();
		} catch (KeyEntryNotFoundException e) {
		}

		assertNull(this.sessionStorageManager.getSessionState(this.card.getId(), sessionId));

	}

	@Test
	public void orphanedSessionKeys() throws SessionManagerException {
		int expireTime = 10;
		int exhaustTime = 10;

		KeyPair keyPair = this.crypto.generateKeys();

		PublishCardRequest identityRequest = instantiateCreateCardRequest(keyPair);

		CardModel card = this.virgilClient.publishCard(identityRequest);
		this.initializeRotator(keyPair.getPrivateKey(), card, 100, exhaustTime, 100, 100);
		this.initializeSessionManager(card, expireTime);

		this.keysRotator.rotateKeys(0);

		Map<String, List<KeyAttrs>> keyAttrs = this.keyStorageManager.getAllKeysAttrs();
		assertEquals(0, keyAttrs.get(KeyStorageManager.SESSION_KEYS).size());
		assertEquals(0, this.sessionStorageManager.getAllSessionsStates().size());

		RecipientCardsSet cardsSet = new RecipientCardsSet(this.ltCard, this.otCard);
		SecureSession session = this.sessionManager.initializeInitiatorSession(this.card, cardsSet, null);
		byte[] sessionId = session.getIdentifier();

		this.sessionStorageManager.removeSessionState(this.card.getId(), sessionId);

		this.keysRotator.rotateKeys(0);

		keyAttrs = this.keyStorageManager.getAllKeysAttrs();
		assertEquals(0, keyAttrs.get(KeyStorageManager.SESSION_KEYS).size());

		try {
			this.keyStorageManager.getSessionKeys(sessionId);
			fail();
		} catch (KeyEntryNotFoundException e) {
		}
	}

	@Test
	public void removeOrhpanedOtcUsed() throws InterruptedException, CryptoException {
		int exhaustTime = 10;

		KeyPair keyPair = this.crypto.generateKeys();

		PublishCardRequest identityRequest = instantiateCreateCardRequest(keyPair);

		CardModel card = this.virgilClient.publishCard(identityRequest);
		this.initializeRotator(keyPair.getPrivateKey(), card, exhaustTime, 100, 100, 100);

		String cardId = card.getId();

		this.keysRotator.rotateKeys(10);

		Map<String, List<KeyAttrs>> keyAttrs = this.keyStorageManager.getAllKeysAttrs();
		assertEquals(10, keyAttrs.get(KeyStorageManager.OT_KEYS).size());

		List<RecipientCardsSet> cardsSets = this.pfsClient.getRecipientCardsSet(cardId);
		assertEquals(1, cardsSets.size());

		RecipientCardsSet cardsSet = cardsSets.get(0);
		assertNotNull(cardsSet.getOneTimeCard());

		String ltId = cardsSet.getLongTermCard().getId();
		String otId = cardsSet.getOneTimeCard().getId();

		this.keyStorageManager.getOtPrivateKey(otId);
		this.keyStorageManager.getLtPrivateKey(ltId);

		this.keysRotator.rotateKeys(10);
		this.keyStorageManager.getOtPrivateKey(otId);

		// Simulate ot key usage
		this.keyStorageManager.removeOtPrivateKey(otId);

		Thread.sleep(exhaustTime * 1000);

		this.keysRotator.rotateKeys(10);
	}

	@Test
	public void removeExhaustedSessionAlreadyRemoved() throws InterruptedException, SessionManagerException {
		int expireTime = 10;
		int exhaustTime = 10;

		KeyPair keyPair = this.crypto.generateKeys();

		PublishCardRequest identityRequest = instantiateCreateCardRequest(keyPair);

		CardModel card = this.virgilClient.publishCard(identityRequest);
		this.initializeRotator(keyPair.getPrivateKey(), card, 100, exhaustTime, 100, 100);
		this.initializeSessionManager(card, expireTime);

		this.keysRotator.rotateKeys(0);

		Map<String, List<KeyAttrs>> keyAttrs = this.keyStorageManager.getAllKeysAttrs();
		assertEquals(0, keyAttrs.get(KeyStorageManager.SESSION_KEYS).size());
		assertEquals(0, this.sessionStorageManager.getAllSessionsStates().size());

		RecipientCardsSet cardsSet = new RecipientCardsSet(this.ltCard, this.otCard);
		SecureSession session = this.sessionManager.initializeInitiatorSession(this.card, cardsSet, null);
		byte[] sessionId = session.getIdentifier();

		keyAttrs = this.keyStorageManager.getAllKeysAttrs();
		assertEquals(1, keyAttrs.get(KeyStorageManager.SESSION_KEYS).size());
		assertEquals(1, this.sessionStorageManager.getAllSessionsStates().size());

		this.keyStorageManager.getSessionKeys(sessionId);
		assertNotNull(this.sessionStorageManager.getSessionState(this.card.getId(), sessionId));

		this.keysRotator.rotateKeys(0);
		this.keyStorageManager.getSessionKeys(sessionId);
		assertNotNull(this.sessionStorageManager.getSessionState(this.card.getId(), sessionId));

		Thread.sleep(expireTime * 1000);

		this.keysRotator.rotateKeys(0);

		this.sessionManager.removeSessions(this.card.getId());

		try {
			this.keyStorageManager.getSessionKeys(sessionId);
			fail();
		} catch (KeyEntryNotFoundException e) {
		}

		assertNull(this.sessionStorageManager.getSessionState(this.card.getId(), sessionId));

		Thread.sleep(exhaustTime * 1000);

		this.keysRotator.rotateKeys(0);
	}

	private void initializeRotator(PrivateKey privateKey, CardModel card, int exhaustedOneTimeCardTtl,
			int expiredSessionTtl, int longTermKeysTtl, int expiredLongTermCardTtl) {
		this.keyStorageManager = new KeyStorageManager(crypto, keyStorage, card.getId());
		EphemeralCardsReplenisher replenisher = new EphemeralCardsReplenisher(crypto, privateKey, card.getId(),
				this.pfsClient, keyStorageManager);

		this.sessionStorageManager = new SessionStorageManager(card.getId(), storage);

		ExhaustInfoManager exhaustInfoManager = new ExhaustInfoManager(card.getId(), storage);

		this.keysRotator = new KeysRotator(card, exhaustedOneTimeCardTtl, expiredSessionTtl, longTermKeysTtl,
				expiredLongTermCardTtl, replenisher, sessionStorageManager, keyStorageManager, exhaustInfoManager,
				this.pfsClient);
	}

	private void initializeSessionManager(CardModel card, int sessionTtl) {
		SessionStorageManager sessionStorageManager = new SessionStorageManager(card.getId(), storage);

		PrivateKey privateKey = this.crypto.generateKeys().getPrivateKey();
		SessionInitializer sessionInitializer = new SessionInitializer(this.crypto, privateKey, card);
		this.sessionManager = new SessionManager(card, privateKey, this.crypto, sessionTtl, this.keyStorageManager,
				sessionStorageManager, sessionInitializer);
	}

}
