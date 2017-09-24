/*
 * Copyright (c) 2017, Virgil Security, Inc.
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of virgil nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.virgilsecurity.sdk.securechat;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.RequestSigner;
import com.virgilsecurity.sdk.client.VirgilClient;
import com.virgilsecurity.sdk.client.exceptions.CardValidationException;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.device.DefaultDeviceManager;
import com.virgilsecurity.sdk.pfs.BaseIT;
import com.virgilsecurity.sdk.pfs.VirgilPFSClient;
import com.virgilsecurity.sdk.pfs.VirgilPFSClientContext;
import com.virgilsecurity.sdk.pfs.model.RecipientCardsSet;
import com.virgilsecurity.sdk.securechat.exceptions.NoSessionException;
import com.virgilsecurity.sdk.securechat.exceptions.SecureChatException;
import com.virgilsecurity.sdk.securechat.exceptions.SessionManagerException;
import com.virgilsecurity.sdk.securechat.impl.DefaultUserDataStorage;
import com.virgilsecurity.sdk.securechat.keystorage.JsonFileKeyStorage;
import com.virgilsecurity.sdk.securechat.model.MessageType;
import com.virgilsecurity.sdk.securechat.session.SecureSession;

/**
 * 
 * @author Andrii Iakovenko
 *
 */
public class SecureChatTest extends BaseIT {

	private static final String USERNAME_IDENTITY_TYPE = "username";
	private static final String MESSAGE1 = "Message 1";
	private static final String MESSAGE2 = "Message 2";
	private static final String MESSAGE3 = "Message 3";
	private static final String MESSAGE4 = "Message 4";
	private static final String MESSAGE5 = "Message 5";
	private static final String MESSAGE6 = "Message 6";

	private VirgilPFSClientContext ctx;
	private Crypto crypto;
	private VirgilClient client;
	private VirgilPFSClient pfsClient;
	private RequestSigner requestSigner;
	private PrivateKey appKey;

	private String aliceIdentity;
	private String bobIdentity;

	private CardModel aliceCard;
	private CardModel bobCard;

	private KeyPair aliceKeys;
	private KeyPair bobKeys;

	private SecureChatContext aliceChatContext;
	private SecureChatContext bobChatContext;

	private SecureChat aliceChat;
	private SecureChat bobChat;

	private int numberOfCards;

	@Before
	public void setUp() throws MalformedURLException, VirgilException {
		// Initialize Crypto
		crypto = new VirgilCrypto();

		// Prepare context
		ctx = new VirgilPFSClientContext(APP_TOKEN);

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

		this.numberOfCards = 5;

		client = new VirgilClient(ctx);
		pfsClient = new VirgilPFSClient(ctx);
		requestSigner = new RequestSigner(crypto);

		appKey = crypto.importPrivateKey(APP_PRIVATE_KEY.getBytes(), APP_PRIVATE_KEY_PASSWORD);

		// Create alice card
		aliceIdentity = "alice" + UUID.randomUUID().toString();
		bobIdentity = "bob" + UUID.randomUUID().toString();

		aliceKeys = crypto.generateKeys();
		aliceCard = publishCard(aliceIdentity, aliceKeys);

		bobKeys = crypto.generateKeys();
		bobCard = publishCard(bobIdentity, bobKeys);

		aliceChatContext = new SecureChatContext(aliceCard, aliceKeys.getPrivateKey(), crypto, ctx);
		aliceChatContext.setKeyStorage(new JsonFileKeyStorage(System.getProperty("java.io.tmpdir"), aliceIdentity));
		aliceChatContext.setDeviceManager(new DefaultDeviceManager());
		aliceChatContext.setUserDataStorage(new DefaultUserDataStorage());
		aliceChat = new SecureChat(aliceChatContext);

		bobChatContext = new SecureChatContext(bobCard, bobKeys.getPrivateKey(), crypto, ctx);
		bobChatContext.setKeyStorage(new JsonFileKeyStorage(System.getProperty("java.io.tmpdir"), bobIdentity));
		bobChatContext.setDeviceManager(new DefaultDeviceManager());
		bobChatContext.setUserDataStorage(new DefaultUserDataStorage());
		bobChat = new SecureChat(bobChatContext);
	}

	@Test
	public void createAndInitializeSecureChat() {
		aliceChat.rotateKeys(this.numberOfCards);
	}

	@Test
	public void initiateSecureSession() throws CardValidationException, SecureChatException {
		aliceChat.rotateKeys(this.numberOfCards);
		SecureSession aliceSession = aliceChat.startNewSession(aliceCard, null);

		assertNotNull(aliceSession);
	}

	@Test
	public void setupSession() throws CardValidationException, SecureChatException, NoSessionException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull(aliceSession);

		String encryptedMessage = aliceSession.encrypt(SecureChatTest.MESSAGE1);
		assertNotNull(encryptedMessage);
		assertTrue(encryptedMessage.length() > 0);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage, null);
		assertNotNull(bobSession);

		String decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertNotNull(decryptedMessage);
		assertEquals(MESSAGE1, decryptedMessage);
	}

	@Test
	public void setupSessionEncryptDecrypt() throws CardValidationException, SecureChatException, NoSessionException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull(aliceSession);

		String encryptedMessage = aliceSession.encrypt(SecureChatTest.MESSAGE1);
		assertNotNull(encryptedMessage);
		assertTrue(encryptedMessage.length() > 0);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage, null);
		assertNotNull(bobSession);

		String decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertNotNull(decryptedMessage);
		assertEquals(MESSAGE1, decryptedMessage);

		String encryptedMessage2 = aliceSession.encrypt(SecureChatTest.MESSAGE2);
		assertNotNull(encryptedMessage2);
		assertTrue(encryptedMessage2.length() > 0);

		String decryptedMessage2 = bobSession.decrypt(encryptedMessage2);
		assertNotNull(decryptedMessage2);
		assertEquals(MESSAGE2, decryptedMessage2);

		String encryptedMessage3 = aliceSession.encrypt(SecureChatTest.MESSAGE3);
		assertNotNull(encryptedMessage3);
		assertTrue(encryptedMessage3.length() > 0);

		String decryptedMessage3 = bobSession.decrypt(encryptedMessage3);
		assertNotNull(decryptedMessage3);
		assertEquals(MESSAGE3, decryptedMessage3);
	}

	@Test
	public void recoverInitiatorSession() throws CardValidationException, SecureChatException, NoSessionException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull(aliceSession);

		String encryptedMessage = aliceSession.encrypt(SecureChatTest.MESSAGE1);
		assertNotNull(encryptedMessage);
		assertTrue(encryptedMessage.length() > 0);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage, null);
		assertNotNull(bobSession);

		String decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertNotNull(decryptedMessage);
		assertEquals(MESSAGE1, decryptedMessage);

		SecureSession recoveredAliceSession = aliceChat.activeSession(bobCard.getId());

		String encryptedMessage2 = recoveredAliceSession.encrypt(SecureChatTest.MESSAGE2);
		assertNotNull(encryptedMessage2);
		assertTrue(encryptedMessage2.length() > 0);

		String decryptedMessage2 = bobSession.decrypt(encryptedMessage2);
		assertNotNull(decryptedMessage2);
		assertEquals(MESSAGE2, decryptedMessage2);
	}

	@Test
	public void recoverInitiatorSessionWithMessage()
			throws CardValidationException, SecureChatException, NoSessionException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage = aliceSession.encrypt(SecureChatTest.MESSAGE1);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage, null);
		String encryptedMessage2 = bobSession.encrypt(SecureChatTest.MESSAGE2);

		SecureSession recoveredAliceSession = aliceChat.loadUpSession(bobCard, encryptedMessage2, null);
		assertNotNull(recoveredAliceSession);

		String decryptedMessage2 = recoveredAliceSession.decrypt(encryptedMessage2);
		assertNotNull(decryptedMessage2);
		assertEquals(MESSAGE2, decryptedMessage2);
	}

	@Test
	public void recoverResponderSession() throws CardValidationException, SecureChatException, NoSessionException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
		SecureSession recoveredBobSession = bobChat.activeSession(aliceCard.getId());
		assertNotNull(recoveredBobSession);

		String encryptedMessage2 = aliceSession.encrypt(SecureChatTest.MESSAGE2);

		String decryptedMessage2 = recoveredBobSession.decrypt(encryptedMessage2);
		assertNotNull(decryptedMessage2);
		assertEquals(MESSAGE2, decryptedMessage2);
	}

	@Test
	public void recoverResponderSessionWithMessage()
			throws CardValidationException, SecureChatException, NoSessionException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);

		String encryptedMessage2 = aliceSession.encrypt(SecureChatTest.MESSAGE2);

		SecureSession recoveredBobSession = bobChat.loadUpSession(aliceCard, encryptedMessage2, null);
		assertNotNull(recoveredBobSession);

		String decryptedMessage2 = recoveredBobSession.decrypt(encryptedMessage2);
		assertNotNull(decryptedMessage2);
		assertEquals(MESSAGE2, decryptedMessage2);
	}

	@Test
	public void expireInitiatorSession()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		aliceChatContext.setSessionTtl(5);
		aliceChat = new SecureChat(aliceChatContext);

		bobChatContext.setSessionTtl(5);
		bobChat = new SecureChat(bobChatContext);

		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);

		String encryptedMessage2 = aliceSession.encrypt(SecureChatTest.MESSAGE2);

		Thread.sleep(10000);

		SecureSession outdatedAliceSession = aliceChat.activeSession(bobCard.getId());
		assertNull(outdatedAliceSession);

		SecureSession outdatedBobSession = bobChat.activeSession(aliceCard.getId());
		assertNull(outdatedBobSession);

		aliceChat.rotateKeys(this.numberOfCards);

		// Double rotate helps to check that we removed keys correctly
		aliceChat.rotateKeys(this.numberOfCards);
	}

	@Test
	public void expireResponderSession()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		aliceChatContext.setSessionTtl(5);
		aliceChat = new SecureChat(aliceChatContext);

		bobChatContext.setSessionTtl(5);
		bobChat = new SecureChat(bobChatContext);

		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);

		String encryptedMessage2 = aliceSession.encrypt(SecureChatTest.MESSAGE2);

		// Wait for expiration
		Thread.sleep(10000);

		SecureSession outdatedAliceSession = aliceChat.activeSession(bobCard.getId());
		assertNull(outdatedAliceSession);

		SecureSession outdatedBobSession = bobChat.activeSession(aliceCard.getId());
		assertNull(outdatedBobSession);

		bobChat.rotateKeys(this.numberOfCards);

		// Double rotate helps to check that we removed keys correctly
		bobChat.rotateKeys(this.numberOfCards);
	}

	@Test
	public void expireLongTermCard()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		int expirationTime = 5;
		int exhaustTime = 5;

		bobChatContext.setLongTermKeysTtl(expirationTime);
		bobChatContext.setExpiredLongTermKeysTtl(exhaustTime);
		bobChat = new SecureChat(bobChatContext);

		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		List<RecipientCardsSet> cardsSet = pfsClient.getRecipientCardsSet(bobCard.getId());
		assertEquals(1, cardsSet.size());

		RecipientCardsSet cardSet = cardsSet.get(0);
		String longTermId1 = cardSet.getLongTermCard().getId();
		String oneTimeId1 = cardSet.getOneTimeCard().getId();

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
		String decryptedMessage1 = bobSession.decrypt(encryptedMessage1);
		assertEquals(MESSAGE1, decryptedMessage1);

		Thread.sleep((expirationTime + exhaustTime) * 1000);

		bobChat.rotateKeys(numberOfCards);

		cardsSet = pfsClient.getRecipientCardsSet(bobCard.getId());
		assertEquals(1, cardsSet.size());

		cardSet = cardsSet.get(0);
		String longTermId2 = cardSet.getLongTermCard().getId();
		String oneTimeId2 = cardSet.getOneTimeCard().getId();

		assertFalse(StringUtils.isBlank(longTermId1));
		assertFalse(StringUtils.isBlank(longTermId2));
		assertNotEquals(longTermId1, longTermId2);

		assertFalse(StringUtils.isBlank(oneTimeId1));
		assertFalse(StringUtils.isBlank(oneTimeId2));
		assertNotEquals(oneTimeId1, oneTimeId2);

		String encryptedMessage2 = aliceSession.encrypt(SecureChatTest.MESSAGE2);

		bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage2, null);
		String decryptedMessage2 = bobSession.decrypt(encryptedMessage2);
		assertEquals(MESSAGE2, decryptedMessage2);
	}

	@Test
	public void forceWeakSession()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(1);

		List<RecipientCardsSet> cardsSet = pfsClient.getRecipientCardsSet(bobCard.getId());
		assertFalse(StringUtils.isBlank(cardsSet.get(0).getOneTimeCard().getId()));

		cardsSet = pfsClient.getRecipientCardsSet(bobCard.getId());
		RecipientCardsSet cardSet = cardsSet.get(0);
		assertNotNull(cardSet.getLongTermCard());
		assertNull(cardSet.getOneTimeCard());

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
		String decryptedMessage1 = bobSession.decrypt(encryptedMessage1);
		assertEquals(MESSAGE1, decryptedMessage1);

		String encryptedMessage2 = aliceSession.encrypt(SecureChatTest.MESSAGE2);
		String decryptedMessage2 = bobSession.decrypt(encryptedMessage2);
		assertEquals(MESSAGE2, decryptedMessage2);

		String encryptedMessage3 = bobSession.encrypt(SecureChatTest.MESSAGE3);
		String decryptedMessage3 = aliceSession.decrypt(encryptedMessage3);
		assertEquals(MESSAGE3, decryptedMessage3);
	}

	@Test
	public void start2SeparateResponderSessions()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		KeyPair bobKeys2 = crypto.generateKeys();
		CardModel bobCard2 = publishCard(bobIdentity, bobKeys2);

		SecureChatContext bobChatContext2 = new SecureChatContext(bobCard2, bobKeys2.getPrivateKey(), crypto, ctx);
		bobChatContext2.setKeyStorage(new JsonFileKeyStorage(System.getProperty("java.io.tmpdir"), bobIdentity));
		bobChatContext2.setDeviceManager(new DefaultDeviceManager());
		bobChatContext2.setUserDataStorage(new DefaultUserDataStorage());
		SecureChat bobChat2 = new SecureChat(bobChatContext2);

		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);
		bobChat2.rotateKeys(this.numberOfCards);

		SecureSession aliceSession1 = aliceChat.startNewSession(bobCard, null);
		assertNotNull(aliceSession1);
		String encryptedMessage11 = aliceSession1.encrypt(SecureChatTest.MESSAGE1);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage11, null);
		String decryptedMessage11 = bobSession.decrypt(encryptedMessage11);
		assertEquals(MESSAGE1, decryptedMessage11);

		SecureSession aliceSession2 = aliceChat.startNewSession(bobCard2, null);
		assertNotNull(aliceSession2);

		String encryptedMessage22 = aliceSession2.encrypt(SecureChatTest.MESSAGE2);
		assertNotNull(encryptedMessage22);
		assertFalse(StringUtils.isBlank(encryptedMessage22));

		SecureSession foreignSession = bobChat2.activeSession(aliceCard.getId());
		assertNull(foreignSession);

		SecureSession bobSession2 = bobChat2.loadUpSession(aliceCard, encryptedMessage22, null);
		assertNotNull(bobSession2);

		String decryptedMessage22 = bobSession2.decrypt(encryptedMessage22);
		assertEquals(MESSAGE2, decryptedMessage22);
	}

	@Test
	public void start2SeparateInitiatorSessions()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		KeyPair aliceKeys2 = crypto.generateKeys();
		CardModel aliceCard2 = publishCard(aliceIdentity, aliceKeys2);

		SecureChatContext aliceChatContext2 = new SecureChatContext(aliceCard2, aliceKeys2.getPrivateKey(), crypto,
				ctx);
		aliceChatContext2.setKeyStorage(new JsonFileKeyStorage(System.getProperty("java.io.tmpdir"), aliceIdentity));
		aliceChatContext2.setDeviceManager(new DefaultDeviceManager());
		aliceChatContext2.setUserDataStorage(new DefaultUserDataStorage());
		SecureChat aliceChat2 = new SecureChat(aliceChatContext2);

		aliceChat.rotateKeys(this.numberOfCards);
		aliceChat2.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession1 = aliceChat.startNewSession(bobCard, null);
		assertNotNull(aliceSession1);
		String encryptedMessage11 = aliceSession1.encrypt(SecureChatTest.MESSAGE1);

		SecureSession bobSession1 = bobChat.loadUpSession(aliceCard, encryptedMessage11, null);
		assertNotNull(bobSession1);
		String decryptedMessage11 = bobSession1.decrypt(encryptedMessage11);
		assertEquals(MESSAGE1, decryptedMessage11);

		SecureSession foreignSession = aliceChat2.activeSession(bobCard.getId());
		assertNull(foreignSession);

		SecureSession aliceSession2 = aliceChat2.startNewSession(bobCard, null);
		assertNotNull(aliceSession2);

		String encryptedMessage22 = aliceSession2.encrypt(SecureChatTest.MESSAGE2);
		assertNotNull(encryptedMessage22);
		assertFalse(StringUtils.isBlank(encryptedMessage22));

		SecureSession bobSession2 = bobChat.loadUpSession(aliceCard2, encryptedMessage22, null);
		assertNotNull(bobSession2);

		String decryptedMessage22 = bobSession2.decrypt(encryptedMessage22);
		assertEquals(MESSAGE2, decryptedMessage22);
	}

	@Test
	public void removeActiveSession()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);

		aliceChat.removeSessions(bobCard.getId());

		SecureSession removedAliceSession = aliceChat.activeSession(bobCard.getId());
		assertNull(removedAliceSession);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
		assertNotNull(bobSession);
		String decryptedMessage1 = bobSession.decrypt(encryptedMessage1);
		assertEquals(MESSAGE1, decryptedMessage1);

		bobChat.removeSessions(aliceCard.getId());

		SecureSession removedBobSession = bobChat.activeSession(aliceCard.getId());
		assertNull(removedBobSession);
	}

	@Test
	public void recreateRemovedActiveSession()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);

		aliceChat.removeSessions(bobCard.getId());

		SecureSession removedAliceSession = aliceChat.activeSession(bobCard.getId());
		assertNull(removedAliceSession);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
		assertNotNull(bobSession);
		String decryptedMessage1 = bobSession.decrypt(encryptedMessage1);
		assertEquals(MESSAGE1, decryptedMessage1);

		bobChat.removeSessions(aliceCard.getId());

		SecureSession removedBobSession = bobChat.activeSession(aliceCard.getId());
		assertNull(removedBobSession);

		SecureSession recreatedAliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull(recreatedAliceSession);

		String encryptedMessage2 = recreatedAliceSession.encrypt(SecureChatTest.MESSAGE2);

		SecureSession recreatedBobSession = bobChat.loadUpSession(aliceCard, encryptedMessage2, null);
		assertNotNull(recreatedBobSession);
		String decryptedMessage2 = recreatedBobSession.decrypt(encryptedMessage2);
		assertEquals(MESSAGE2, decryptedMessage2);
	}

	@Test
	public void restartInvalidSession()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		aliceChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(aliceCard, null);
		assertNotNull(aliceSession);

		aliceChat.removeSessions(aliceCard.getId());

		SecureSession recreatedAliceSession = aliceChat.startNewSession(aliceCard, null);
		assertNotNull(recreatedAliceSession);
	}

	@Test
	public void secureChatDoubleInitialization()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		aliceChat.rotateKeys(this.numberOfCards);

		SecureChat aliceChat2 = new SecureChat(aliceChatContext);
		aliceChat2.rotateKeys(this.numberOfCards);
	}

	@Test
	public void secureSessionTimeExpiration()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		int expireTime = 5;
		aliceChatContext.setSessionTtl(expireTime);
		aliceChat = new SecureChat(aliceChatContext);

		bobChatContext.setSessionTtl(expireTime);
		bobChat = new SecureChat(bobChatContext);

		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
		assertNotNull(bobSession);
		String decryptedMessage1 = bobSession.decrypt(encryptedMessage1);
		assertEquals(MESSAGE1, decryptedMessage1);

		String encryptedMessage2 = aliceSession.encrypt(SecureChatTest.MESSAGE2);

		Thread.sleep(expireTime * 10000);

		assertTrue(aliceSession.isExpired(new Date()));
		assertTrue(bobSession.isExpired(new Date()));
		assertNull(aliceChat.activeSession(bobCard.getId()));

		SecureSession bobSession2 = bobChat.loadUpSession(aliceCard, encryptedMessage2, null);
		assertNotNull(bobSession2);
		assertTrue(bobSession2.isExpired(new Date()));
		String decryptedMessage2 = bobSession.decrypt(encryptedMessage2);
		assertEquals(MESSAGE2, decryptedMessage2);
	}

	@Test
	public void recreateExpiredSession()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		int expireTime = 5;
		aliceChatContext.setSessionTtl(expireTime);
		aliceChat = new SecureChat(aliceChatContext);

		bobChatContext.setSessionTtl(expireTime);
		bobChat = new SecureChat(bobChatContext);

		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
		assertNotNull(bobSession);
		String decryptedMessage1 = bobSession.decrypt(encryptedMessage1);
		assertEquals(MESSAGE1, decryptedMessage1);

		Thread.sleep(expireTime * 10000);

		SecureSession aliceSession2 = aliceChat.startNewSession(bobCard, null);
		assertNotNull(aliceSession2);
		String encryptedMessage2 = aliceSession2.encrypt(SecureChatTest.MESSAGE2);

		SecureSession bobSession2 = bobChat.loadUpSession(aliceCard, encryptedMessage2, null);
		assertNotNull(bobSession2);
		String decryptedMessage2 = bobSession2.decrypt(encryptedMessage2);
		assertEquals(MESSAGE2, decryptedMessage2);
	}

	@Test
	public void setupSessionCheckMessageType()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);
		assertThat(SecureChat.getMessageType(encryptedMessage1), is(MessageType.INITIAL));

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
		assertNotNull(bobSession);
		String decryptedMessage1 = bobSession.decrypt(encryptedMessage1);
		assertEquals(MESSAGE1, decryptedMessage1);

		String encryptedMessage2 = aliceSession.encrypt(SecureChatTest.MESSAGE2);
		assertThat(SecureChat.getMessageType(encryptedMessage2), is(MessageType.REGULAR));

		assertThat(SecureChat.getMessageType("garbage"), is(MessageType.UNKNOWN));
	}

	@Test
	public void gentleReset()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
		assertNotNull(bobSession);
		String decryptedMessage1 = bobSession.decrypt(encryptedMessage1);
		assertEquals(MESSAGE1, decryptedMessage1);

		String encryptedMessage2 = aliceSession.encrypt(SecureChatTest.MESSAGE2);

		aliceChat.gentleReset();
		bobChat.gentleReset();

		try {
			bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
			fail();
		} catch (KeyEntryNotFoundException e) {
		}

		try {
			bobChat.loadUpSession(aliceCard, encryptedMessage2, null);
			fail();
		} catch (SessionManagerException e) {
		}

		SecureSession aliceSession2 = aliceChat.activeSession(bobCard.getId());
		assertNull(aliceSession2);
	}

	@Test
	public void createAndInitializeSecureChatConcurrent() throws CardValidationException, SecureChatException,
			NoSessionException, InterruptedException, ExecutionException {

		FutureTask<Void> f1 = new FutureTask<Void>(new Callable<Void>() {
			public Void call() {
				aliceChat.rotateKeys(5);
				return null;
			}
		});
		FutureTask<Void> f2 = new FutureTask<Void>(new Callable<Void>() {
			public Void call() {
				aliceChat.rotateKeys(100);
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
	public void multipleSessions()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {

		int sessionTtl = 5;
		aliceChatContext.setSessionTtl(sessionTtl);
		aliceChat = new SecureChat(aliceChatContext);

		bobChatContext.setSessionTtl(sessionTtl);
		bobChat = new SecureChat(bobChatContext);

		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);
		String encryptedMessage3 = aliceSession.encrypt(SecureChatTest.MESSAGE3);

		aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage2 = aliceSession.encrypt(SecureChatTest.MESSAGE2);
		String encryptedMessage4 = aliceSession.encrypt(SecureChatTest.MESSAGE4);

		SecureSession bobSession1 = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
		String decryptedMessage1 = bobSession1.decrypt(encryptedMessage1);
		assertEquals(MESSAGE1, decryptedMessage1);
		String decryptedMessage3 = bobSession1.decrypt(encryptedMessage3);
		assertEquals(MESSAGE3, decryptedMessage3);

		SecureSession bobSession2 = bobChat.loadUpSession(aliceCard, encryptedMessage2, null);
		String decryptedMessage2 = bobSession2.decrypt(encryptedMessage2);
		assertEquals(MESSAGE2, decryptedMessage2);
		String decryptedMessage4 = bobSession2.decrypt(encryptedMessage4);
		assertEquals(MESSAGE4, decryptedMessage4);

		String encryptedMessage5 = bobSession1.encrypt(SecureChatTest.MESSAGE5);
		SecureSession aliceSession1 = aliceChat.loadUpSession(bobCard, encryptedMessage5, null);
		String decryptedMessage5 = aliceSession1.decrypt(encryptedMessage5);
		assertEquals(MESSAGE5, decryptedMessage5);

		String encryptedMessage6 = bobSession2.encrypt(SecureChatTest.MESSAGE6);
		SecureSession aliceSession2 = aliceChat.loadUpSession(bobCard, encryptedMessage6, null);
		String decryptedMessage6 = aliceSession2.decrypt(encryptedMessage6);
		assertEquals(MESSAGE6, decryptedMessage6);
	}

	@Test
	public void multipleSessionsRemoveOne()
			throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {

		int sessionTtl = 5;
		aliceChatContext.setSessionTtl(sessionTtl);
		aliceChat = new SecureChat(aliceChatContext);

		bobChatContext.setSessionTtl(sessionTtl);
		bobChat = new SecureChat(bobChatContext);

		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage1 = aliceSession.encrypt(SecureChatTest.MESSAGE1);
		String encryptedMessage3 = aliceSession.encrypt(SecureChatTest.MESSAGE3);

		aliceSession = aliceChat.startNewSession(bobCard, null);
		String encryptedMessage2 = aliceSession.encrypt(SecureChatTest.MESSAGE2);
		String encryptedMessage4 = aliceSession.encrypt(SecureChatTest.MESSAGE4);

		SecureSession bobSession1 = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
		String decryptedMessage1 = bobSession1.decrypt(encryptedMessage1);
		assertEquals(MESSAGE1, decryptedMessage1);
		String decryptedMessage3 = bobSession1.decrypt(encryptedMessage3);
		assertEquals(MESSAGE3, decryptedMessage3);

		SecureSession bobSession2 = bobChat.loadUpSession(aliceCard, encryptedMessage2, null);
		String decryptedMessage2 = bobSession2.decrypt(encryptedMessage2);
		assertEquals(MESSAGE2, decryptedMessage2);
		String decryptedMessage4 = bobSession2.decrypt(encryptedMessage4);
		assertEquals(MESSAGE4, decryptedMessage4);

		aliceChat.removeSession(bobCard.getId(), bobSession1.getIdentifier());

		String encryptedMessage5 = bobSession1.encrypt(SecureChatTest.MESSAGE5);
		try {
			aliceChat.loadUpSession(bobCard, encryptedMessage5, null);
			fail();
		} catch (SessionManagerException e) {
		}

		String encryptedMessage6 = bobSession2.encrypt(SecureChatTest.MESSAGE6);
		SecureSession aliceSession2 = aliceChat.loadUpSession(bobCard, encryptedMessage6, null);
		String decryptedMessage6 = aliceSession2.decrypt(encryptedMessage6);
		assertEquals(MESSAGE6, decryptedMessage6);
	}

	@Test
	public void cache() throws CardValidationException, SecureChatException, NoSessionException, InterruptedException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		SecureSession aliceSession1 = aliceChat.activeSession(bobCard.getId());
		assertNotNull(aliceSession1);

		String encryptedMessage1 = aliceSession1.encrypt(SecureChatTest.MESSAGE1);
		String encryptedMessage2 = aliceSession1.encrypt(SecureChatTest.MESSAGE2);

		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1, null);
		assertNotNull(bobSession);

		bobSession = bobChat.activeSession(aliceCard.getId());
		bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage2, null);

		String decryptedMessage1 = bobSession.decrypt(encryptedMessage1);
		assertEquals(MESSAGE1, decryptedMessage1);
	}

	@Test
	public void expireOtCard() throws CardValidationException, SecureChatException, NoSessionException,
			InterruptedException, ExecutionException {
		int exhaustedOneTimeKeysTtl = 5;
		aliceChatContext.setExhaustedOneTimeKeysTtl(exhaustedOneTimeKeysTtl);
		aliceChat = new SecureChat(aliceChatContext);

		aliceChat.rotateKeys(1);

		pfsClient.getRecipientCardsSet(aliceCard.getId());

		aliceChat.rotateKeys(1);

		Thread.sleep(exhaustedOneTimeKeysTtl * 1000);

		aliceChat.rotateKeys(1);
	}

	private CardModel publishCard(String identity, KeyPair keyPair) {
		byte[] exportedPublicKey = crypto.exportPublicKey(keyPair.getPublicKey());
		PublishCardRequest createCardRequest = new PublishCardRequest(identity, USERNAME_IDENTITY_TYPE,
				exportedPublicKey);
		requestSigner.selfSign(createCardRequest, keyPair.getPrivateKey());
		requestSigner.authoritySign(createCardRequest, APP_ID, appKey);

		return client.publishCard(createCardRequest);
	}

}
