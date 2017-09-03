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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.RequestSigner;
import com.virgilsecurity.sdk.client.VirgilClient;
import com.virgilsecurity.sdk.client.exceptions.VirgilClientException;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.model.dto.SearchCriteria;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.device.DefaultDeviceManager;
import com.virgilsecurity.sdk.pfs.BaseIT;
import com.virgilsecurity.sdk.pfs.VirgilPFSClient;
import com.virgilsecurity.sdk.pfs.VirgilPFSClientContext;
import com.virgilsecurity.sdk.pfs.model.RecipientCardsSet;
import com.virgilsecurity.sdk.securechat.impl.DefaultUserDataStorage;
import com.virgilsecurity.sdk.securechat.utils.SessionStateResolver;
import com.virgilsecurity.sdk.storage.DefaultKeyStorage;

/**
 * Expire Alices's session. See expireAliceSession.<br/>
 * Expire Bob's session. See expireBobSession.<br/>
 * Expire long term card. See expireLtc.<br/>
 * Force weak session. See forceWeakSession. <br/>
 * Start 2 separate responder sessions. See start2SeparateBobSessions.<br/>
 * Start 2 separate initiator sessions. See start2SeparateAliceSessions.<br/>
 * Remove active session. See removeActiveSession.<br/>
 * Recreate removed active session. See recreateRemovedActiveSession.<br/>
 * Restart invalid session. See restartInvalidSession.<br/>
 * Secure chat double initialization. See doubleInitialization.<br/>
 * Secure session time expiration. See .<br/>
 * Recreate expired session. See .<br/>
 * Setup session check message type. See .<br/>
 * Gentle reset. See gentleReset.<br/>
 * Create and initialize secure chat concurrent. See
 * createAndInitializeSecureChatConcurrent.
 * 
 * @author Andrii Iakovenko
 *
 */
public class SecureChatTest extends BaseIT {

	private static final String USERNAME_IDENTITY_TYPE = "username";
	private static final String MESSAGE1 = UUID.randomUUID().toString();
	private static final String MESSAGE2 = UUID.randomUUID().toString();
	private static final String MESSAGE3 = UUID.randomUUID().toString();

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
		aliceChatContext.setKeyStorage(new DefaultKeyStorage(System.getProperty("java.io.tmpdir"), aliceIdentity));
		aliceChatContext.setDeviceManager(new DefaultDeviceManager());
		aliceChatContext.setUserDefaults(new DefaultUserDataStorage());
		aliceChat = new SecureChat(aliceChatContext);

		bobChatContext = new SecureChatContext(bobCard, bobKeys.getPrivateKey(), crypto, ctx);
		bobChatContext.setKeyStorage(new DefaultKeyStorage(System.getProperty("java.io.tmpdir"), bobIdentity));
		bobChatContext.setDeviceManager(new DefaultDeviceManager());
		bobChatContext.setUserDefaults(new DefaultUserDataStorage());
		bobChat = new SecureChat(bobChatContext);
	}

	@Test
	public void aliceToBobFlow() throws VirgilException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.activeSession(bobCard.getId());
		assertNull("No active session yet", aliceSession);

		/** Start new session */
		aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);
		assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));
		List<CardModel> aliceCards = client.searchCards(SearchCriteria.byIdentity(aliceIdentity));
		assertFalse("Identity card should be created", aliceCards.isEmpty());

		/** Send first message to Bob */
		String firstMessage = UUID.randomUUID().toString();
		String encryptedFirstMessage = aliceSession.encrypt(firstMessage);
		assertNotNull(encryptedFirstMessage);
		assertTrue(SessionStateResolver.isInitiationMessage(encryptedFirstMessage));

		// Bob receives message and create session
		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedFirstMessage);
		assertNotNull(bobSession);
		assertThat("Bob is responder", bobSession, instanceOf(SecureSessionResponder.class));
		List<CardModel> bobCards = client.searchCards(SearchCriteria.byIdentity(bobIdentity));
		assertFalse("Identity card should be created", bobCards.isEmpty());
		String decryptedFirstMessage = bobSession.decrypt(encryptedFirstMessage);
		assertEquals("Message should be decrypted properly", firstMessage, decryptedFirstMessage);

		/** Send second message to Bob */
		String message = UUID.randomUUID().toString();
		aliceSession = aliceChat.activeSession(bobCard.getId());
		String encryptedMessage = aliceSession.encrypt(message);
		assertNotNull(encryptedMessage);
		assertFalse(SessionStateResolver.isInitiationMessage(encryptedMessage));

		// Bob receives message and decrypts it
		bobSession = bobChat.activeSession(aliceCard.getId());
		assertNotNull("Bob session not found", bobSession);
		String decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertNotNull(decryptedMessage);
		assertEquals("Message should be decrypted properly", message, decryptedMessage);

		/** Send the message to Alice */
		message = UUID.randomUUID().toString();
		encryptedMessage = bobSession.encrypt(message);
		assertNotNull(encryptedMessage);
		assertFalse(SessionStateResolver.isInitiationMessage(encryptedMessage));

		// Alice receives the message and decrypts it
		aliceSession = aliceChat.activeSession(bobCard.getId());
		assertNotNull("Alice session not found", aliceSession);
		decryptedMessage = aliceSession.decrypt(encryptedMessage);
		assertNotNull(decryptedMessage);
		assertEquals("Message should be decrypted properly", message, decryptedMessage);

		/** Recover Alice's session */
		aliceChat = new SecureChat(aliceChatContext);
		aliceSession = aliceChat.activeSession(bobCard.getId());
		assertNotNull(aliceSession);
		assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));

		// Send message to Bob
		message = UUID.randomUUID().toString();
		encryptedMessage = aliceSession.encrypt(message);
		assertNotNull(encryptedMessage);
		assertFalse(SessionStateResolver.isInitiationMessage(encryptedMessage));

		// Bob receives a message
		bobSession = bobChat.activeSession(aliceCard.getId());
		decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertNotNull(decryptedMessage);
		assertEquals("Message should be decrypted properly", message, decryptedMessage);

		/** Recover Bob's session */
		bobChat = new SecureChat(bobChatContext);
		bobSession = bobChat.activeSession(aliceCard.getId());
		assertNotNull(bobSession);
		assertThat("Bob is responder", bobSession, instanceOf(SecureSessionResponder.class));

		// Bob decrypts Alice's message
		decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertNotNull(decryptedMessage);
		assertEquals("Message should be decrypted properly", message, decryptedMessage);

		/** Recover Alices's session by message */
		// Bob sends a message
		message = UUID.randomUUID().toString();
		encryptedMessage = bobSession.encrypt(message);
		assertNotNull(encryptedMessage);
		assertFalse(SessionStateResolver.isInitiationMessage(encryptedMessage));

		// Alice receives a message
		aliceChat = new SecureChat(aliceChatContext);
		aliceSession = aliceChat.loadUpSession(bobCard, encryptedMessage);
		assertNotNull(aliceSession);
		assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));

		/** Recover Bob's session by message */
		// Alice sends a message
		message = UUID.randomUUID().toString();
		encryptedMessage = aliceSession.encrypt(message);
		assertNotNull(encryptedMessage);
		assertFalse(SessionStateResolver.isInitiationMessage(encryptedMessage));

		// Alice receives a message
		bobChat = new SecureChat(bobChatContext);
		bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
		assertNotNull(bobSession);
		assertThat("Alice is initiator", bobSession, instanceOf(SecureSessionResponder.class));
	}

	@Test
	public void expireAliceSession() throws InterruptedException, VirgilException {
		aliceChatContext.setSessionTtl(5);
		aliceChat.rotateKeys(this.numberOfCards);

		bobChatContext.setSessionTtl(5);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.activeSession(bobCard.getId());
		assertNull("No active session yet", aliceSession);

		/** Start new session */
		aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);

		/** Send first message to Bob */
		String message1 = UUID.randomUUID().toString();
		String encryptedMessage1 = aliceSession.encrypt(message1);
		assertNotNull(encryptedMessage1);

		// Bob receives message and create session
		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1);
		assertNotNull(bobSession);

		String message2 = UUID.randomUUID().toString();
		String encryptedMessage2 = aliceSession.encrypt(message2);

		// Wait until Alice session expire
		long waitTime = aliceSession.getExpirationDate().getTime() - new Date().getTime();
		if (waitTime > 0) {
			Thread.sleep(waitTime + 3000);
		}

		assertTrue("Alice session should be expired at the moment", aliceSession.isExpired());

		SecureSession outdatedAliceSession = aliceChat.activeSession(bobCard.getId());
		assertNull(outdatedAliceSession);

		SecureSession outdatedBobSession = bobChat.activeSession(aliceCard.getId());
		assertNull(outdatedBobSession);

		aliceChat.rotateKeys(numberOfCards);
		// Double rotate helps to check that we removed keys correctly
		aliceChat.rotateKeys(numberOfCards);
	}

	@Test
	public void expireBobSession() throws InterruptedException, VirgilException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChatContext.setSessionTtl(10);
		bobChat.rotateKeys(this.numberOfCards);

		SecureSession aliceSession = aliceChat.activeSession(bobCard.getId());
		assertNull("No active session yet", aliceSession);

		/** Start new session */
		aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);
		assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));
		List<CardModel> aliceCards = client.searchCards(SearchCriteria.byIdentity(aliceIdentity));
		assertFalse("Identity card should be created", aliceCards.isEmpty());

		/** Send first message to Bob */
		String firstMessage = UUID.randomUUID().toString();
		String encryptedFirstMessage = aliceSession.encrypt(firstMessage);
		assertNotNull(encryptedFirstMessage);
		assertTrue(SessionStateResolver.isInitiationMessage(encryptedFirstMessage));

		// Bob receives message and create session
		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedFirstMessage);
		assertNotNull(bobSession);
		assertThat("Bob is responder", bobSession, instanceOf(SecureSessionResponder.class));
		List<CardModel> bobCards = client.searchCards(SearchCriteria.byIdentity(bobIdentity));
		assertFalse("Identity card should be created", bobCards.isEmpty());
		String decryptedFirstMessage = bobSession.decrypt(encryptedFirstMessage);
		assertEquals("Message should be decrypted properly", firstMessage, decryptedFirstMessage);

		// Wait until Bob's session expire
		long waitTime = bobSession.getExpirationDate().getTime() - new Date().getTime();
		if (waitTime > 0) {
			Thread.sleep(waitTime + 3000);
		}

		assertTrue("Bob session should be expired at the moment", bobSession.isExpired());
		SecureSession outdatedBobSession = bobChat.activeSession(aliceCard.getId());
		assertNull("Not active Bob's session to Alice at the moment", outdatedBobSession);

		bobChat.rotateKeys(numberOfCards);
		// Double rotate helps to check that we removed keys correctly
		bobChat.rotateKeys(numberOfCards);
	}

	@Test
	public void expireLtc() throws InterruptedException, VirgilException {
		aliceChat.rotateKeys(this.numberOfCards);

		bobChatContext.setLongTermKeysTtl(5);
		bobChat = new SecureChat(bobChatContext);
		bobChat.rotateKeys(this.numberOfCards);

		String longTermId1, longTermId2, oneTimeId1, oneTimeId2;

		List<RecipientCardsSet> cardsSet = pfsClient.getRecipientCardsSet(Arrays.asList(bobCard.getId()));
		assertNotNull(cardsSet);
		assertEquals(1, cardsSet.size());

		RecipientCardsSet cardSet = cardsSet.get(0);
		longTermId1 = cardSet.getLongTermCard().getId();
		assertFalse(com.virgilsecurity.sdk.utils.StringUtils.isBlank(longTermId1));

		oneTimeId1 = cardSet.getOneTimeCard().getId();
		assertFalse(com.virgilsecurity.sdk.utils.StringUtils.isBlank(oneTimeId1));

		/** Start new session */
		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);
		assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));

		/** Send first message to Bob */
		String message = UUID.randomUUID().toString();
		String encryptedMessage = aliceSession.encrypt(message);
		assertNotNull(encryptedMessage);
		assertTrue(SessionStateResolver.isInitiationMessage(encryptedMessage));

		// Bob receives message and create session
		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
		assertNotNull(bobSession);
		assertThat("Bob is responder", bobSession, instanceOf(SecureSessionResponder.class));
		List<CardModel> bobCards = client.searchCards(SearchCriteria.byIdentity(bobIdentity));
		assertFalse("Identity card should be created", bobCards.isEmpty());
		String decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", message, decryptedMessage);

		// Wait until Bob's session expire
		long waitTime = bobSession.getContext().getLongTermKeysTtl() * 1000;
		if (waitTime > 0) {
			Thread.sleep(waitTime + 3000);
		}

		bobChat.rotateKeys(numberOfCards);
		cardsSet = pfsClient.getRecipientCardsSet(bobCard.getId());
		assertNotNull(cardsSet);
		assertEquals(1, cardsSet.size());

		cardSet = cardsSet.get(0);
		longTermId2 = cardSet.getLongTermCard().getId();
		assertFalse(com.virgilsecurity.sdk.utils.StringUtils.isBlank(longTermId2));

		oneTimeId2 = cardSet.getOneTimeCard().getId();
		assertFalse(com.virgilsecurity.sdk.utils.StringUtils.isBlank(longTermId2));

		assertNotEquals(longTermId1, longTermId2);
		assertNotEquals(oneTimeId1, oneTimeId2);

		message = UUID.randomUUID().toString();
		encryptedMessage = aliceSession.encrypt(message);
		bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
		assertNotNull(bobSession);
		decryptedMessage = bobSession.decrypt(encryptedMessage);
	}

	@Test
	public void gentleReset() throws InterruptedException, VirgilException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		/** Start new session */
		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);
		assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));

		/** Send message to Bob */
		String message = UUID.randomUUID().toString();
		String encryptedMessage1 = aliceSession.encrypt(message);
		assertNotNull(encryptedMessage1);
		assertTrue(SessionStateResolver.isInitiationMessage(encryptedMessage1));

		// Bob receives message and create session
		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1);
		assertNotNull(bobSession);

		String decryptedMessage = bobSession.decrypt(encryptedMessage1);
		assertEquals("Message should be decrypted properly", message, decryptedMessage);

		message = UUID.randomUUID().toString();
		String encryptedMessage2 = aliceSession.encrypt(message);

		aliceChat.gentleReset();

		bobChat.gentleReset();

		bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1);
		assertNull(bobSession);

		bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage2);
		assertNull(bobSession);

		aliceSession = aliceChat.activeSession(bobCard.getId());
		assertNull(aliceSession);
	}

	@Test
	public void forceWeakSession() throws VirgilException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		List<RecipientCardsSet> bobCards = pfsClient.getRecipientCardsSet(bobCard.getId());
		assertEquals(1, bobCards.size());
		assertNotNull(bobCards.get(0).getLongTermCard());
		assertNotNull(bobCards.get(0).getOneTimeCard());

		// Start new session
		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);

		// Send message to Bob
		String encryptedMessage = aliceSession.encrypt(MESSAGE1);
		assertNotNull(encryptedMessage);

		// Bob receives message and create session
		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
		assertNotNull(bobSession);

		String decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE1, decryptedMessage);

		encryptedMessage = aliceSession.encrypt(MESSAGE2);
		decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE2, decryptedMessage);

		encryptedMessage = bobSession.encrypt(MESSAGE3);
		decryptedMessage = aliceSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE3, decryptedMessage);
	}

	@Test
	public void start2SeparateBobSessions() throws VirgilException {
		KeyPair bobKeys2 = crypto.generateKeys();
		CardModel bobCard2 = publishCard(bobIdentity, bobKeys2);

		SecureChatContext bobChatContext2 = new SecureChatContext(bobCard2, bobKeys2.getPrivateKey(), crypto, ctx);
		bobChatContext2.setKeyStorage(new DefaultKeyStorage(System.getProperty("java.io.tmpdir"), bobIdentity));
		bobChatContext2.setDeviceManager(new DefaultDeviceManager());
		bobChatContext2.setUserDefaults(new DefaultUserDataStorage());
		SecureChat bobChat2 = new SecureChat(bobChatContext2);

		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);
		bobChat2.rotateKeys(this.numberOfCards);

		// Start new session to Bob
		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);

		// Send message to Bob
		String encryptedMessage = aliceSession.encrypt(MESSAGE1);
		assertNotNull(encryptedMessage);

		// Bob receives message and create session
		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
		assertNotNull(bobSession);

		String decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE1, decryptedMessage);

		// Start new session to Bob2
		SecureSession aliceSession2 = aliceChat.startNewSession(bobCard2, null);
		assertNotNull("Security session should be created", aliceSession2);

		// Send message to Bob
		encryptedMessage = aliceSession2.encrypt(MESSAGE1);
		assertNotNull(encryptedMessage);

		// Try to catch foreign session
		SecureSession foreignSession = bobChat2.activeSession(aliceCard.getId());
		assertNull(foreignSession);

		// Bob receives message and create session
		SecureSession bobSession2 = bobChat2.loadUpSession(aliceCard, encryptedMessage);
		assertNotNull(bobSession2);

		decryptedMessage = bobSession2.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE1, decryptedMessage);

		// Chat with Bob
		encryptedMessage = aliceSession.encrypt(MESSAGE2);
		decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE2, decryptedMessage);

		encryptedMessage = bobSession.encrypt(MESSAGE3);
		decryptedMessage = aliceSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE3, decryptedMessage);

		// Chat with Bob2
		encryptedMessage = aliceSession2.encrypt(MESSAGE2);
		decryptedMessage = bobSession2.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE2, decryptedMessage);

		encryptedMessage = bobSession2.encrypt(MESSAGE3);
		decryptedMessage = aliceSession2.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE3, decryptedMessage);
	}

	@Test
	public void start2SeparateAliceSessions() throws VirgilException {
		KeyPair aliceKeys2 = crypto.generateKeys();
		CardModel aliceCard2 = publishCard(aliceIdentity, aliceKeys2);

		SecureChatContext aliceChatContext2 = new SecureChatContext(aliceCard2, aliceKeys2.getPrivateKey(), crypto,
				ctx);
		aliceChatContext2.setKeyStorage(new DefaultKeyStorage(System.getProperty("java.io.tmpdir"), aliceIdentity));
		aliceChatContext2.setDeviceManager(new DefaultDeviceManager());
		aliceChatContext2.setUserDefaults(new DefaultUserDataStorage());
		SecureChat aliceChat2 = new SecureChat(aliceChatContext2);

		aliceChat.rotateKeys(this.numberOfCards);
		aliceChat2.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		// Start new session to Bob
		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);

		// Send message to Bob
		String encryptedMessage = aliceSession.encrypt(MESSAGE1);
		assertNotNull(encryptedMessage);

		// Bob receives message and create session
		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
		assertNotNull(bobSession);

		String decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE1, decryptedMessage);

		// Try to catch foreign session
		SecureSession foreignSession = aliceChat2.activeSession(bobCard.getId());
		assertNull(foreignSession);

		// Start new session to Bob2
		SecureSession aliceSession2 = aliceChat2.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession2);

		// Send message to Bob
		encryptedMessage = aliceSession2.encrypt(MESSAGE1);
		assertNotNull(encryptedMessage);

		// Bob receives message and create session
		SecureSession bobSession2 = bobChat.loadUpSession(aliceCard2, encryptedMessage);
		assertNotNull(bobSession2);

		decryptedMessage = bobSession2.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE1, decryptedMessage);

		// Chat Alice with Bob
		encryptedMessage = aliceSession.encrypt(MESSAGE2);
		decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE2, decryptedMessage);

		encryptedMessage = bobSession.encrypt(MESSAGE3);
		decryptedMessage = aliceSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE3, decryptedMessage);

		// Chat Alice 2 with Bob
		encryptedMessage = aliceSession2.encrypt(MESSAGE2);
		decryptedMessage = bobSession2.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE2, decryptedMessage);

		encryptedMessage = bobSession2.encrypt(MESSAGE3);
		decryptedMessage = aliceSession2.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE3, decryptedMessage);
	}

	@Test
	public void removeActiveSession() throws VirgilException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		// Start new session
		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);
		assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));

		// Send message to Bob
		String message = UUID.randomUUID().toString();
		String encryptedMessage1 = aliceSession.encrypt(message);
		assertNotNull(encryptedMessage1);
		assertTrue(SessionStateResolver.isInitiationMessage(encryptedMessage1));

		// Remove Alice's session
		aliceChat.removeSession(bobCard.getId());

		SecureSession removedAliceSession = aliceChat.activeSession(bobCard.getId());
		assertNull(removedAliceSession);

		// Bob receives message and create session
		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1);
		assertNotNull(bobSession);

		String decryptedMessage = bobSession.decrypt(encryptedMessage1);
		assertEquals("Message should be decrypted properly", message, decryptedMessage);

		// Remove Bob's session
		bobChat.removeSession(aliceCard.getId());
		SecureSession removedBobSession = bobChat.activeSession(aliceCard.getId());
		assertNull(removedBobSession);
	}

	@Test
	public void recreateRemovedActiveSession() throws VirgilException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		// Start new session
		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);

		// Send message to Bob
		String encryptedMessage = aliceSession.encrypt(MESSAGE1);
		assertNotNull(encryptedMessage);

		// Remove Alice's session
		aliceChat.removeSession(bobCard.getId());

		SecureSession removedAliceSession = aliceChat.activeSession(bobCard.getId());
		assertNull(removedAliceSession);

		// Bob receives message and create session
		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
		assertNotNull(bobSession);

		String decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE1, decryptedMessage);

		// Remove Bob's session
		bobChat.removeSession(aliceCard.getId());
		SecureSession removedBobSession = bobChat.activeSession(aliceCard.getId());
		assertNull(removedBobSession);

		// Start new session
		aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);

		// Send message to Bob
		encryptedMessage = aliceSession.encrypt(MESSAGE2);
		assertNotNull(encryptedMessage);

		// Bob receives message and create session
		bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
		assertNotNull(bobSession);

		decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE2, decryptedMessage);
	}

	@Test
	public void restartInvalidSession() throws VirgilException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		// Start new session
		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);

		// Remove Alice's session
		aliceChat.removeSession(bobCard.getId());

		SecureSession removedAliceSession = aliceChat.activeSession(bobCard.getId());
		assertNull(removedAliceSession);

		// Start new session
		aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);
	}

	@Test
	public void doubleInitialization() throws VirgilException, InterruptedException {
		KeyPair aliceKeys2 = crypto.generateKeys();
		CardModel aliceCard2 = publishCard(aliceIdentity, aliceKeys2);

		SecureChatContext aliceChatContext2 = new SecureChatContext(aliceCard2, aliceKeys2.getPrivateKey(), crypto,
				ctx);
		aliceChatContext2.setKeyStorage(new DefaultKeyStorage(System.getProperty("java.io.tmpdir"), aliceIdentity));
		aliceChatContext2.setDeviceManager(new DefaultDeviceManager());
		aliceChatContext2.setUserDefaults(new DefaultUserDataStorage());
		final SecureChat aliceChat2 = new SecureChat(aliceChatContext2);

		aliceChat.rotateKeys(numberOfCards);
		aliceChat2.rotateKeys(numberOfCards);
	}

	@Test
	public void createAndInitializeSecureChatConcurrent() throws VirgilException, InterruptedException {
		Thread t1 = new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					aliceChat.rotateKeys(numberOfCards);
				} catch (VirgilException e) {
					fail(e.getMessage());
				}
			}
		});
		Thread t2 = new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					aliceChat.rotateKeys(numberOfCards);
				} catch (VirgilException e) {
					fail(e.getMessage());
				}
			}
		});

		t1.start();
		t2.start();
		t1.join();
		t2.join();
	}

	@Test
	public void rotateKeysAndDecrypt() throws VirgilException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		// Start new session
		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);

		// Send message to Bob
		String encryptedMessage = aliceSession.encrypt(MESSAGE1);
		assertNotNull(encryptedMessage);

		// Bob rotates keys
		bobChat.rotateKeys(this.numberOfCards);

		// Bob receives message and creates session
		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
		assertNotNull(bobSession);

		String decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE1, decryptedMessage);
	}

	@Test
	public void rotateKeysAndDecrypt2() throws VirgilException {
		aliceChat.rotateKeys(this.numberOfCards);
		bobChat.rotateKeys(this.numberOfCards);

		// Start new session
		SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotNull("Security session should be created", aliceSession);

		// Send message to Bob
		String encryptedMessage = aliceSession.encrypt(MESSAGE1);
		assertNotNull(encryptedMessage);

		String encryptedMessage2 = aliceSession.encrypt(MESSAGE2);
		assertNotNull(encryptedMessage);

		// Bob rotates keys
		bobChat.rotateKeys(this.numberOfCards);

		// Bob receives message and creates session
		SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
		assertNotNull(bobSession);

		String decryptedMessage = bobSession.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE1, decryptedMessage);

		aliceChat.removeSession(bobCard.getId());
		SecureSession newAliceSession = aliceChat.startNewSession(bobCard, null);
		assertNotSame(aliceSession, newAliceSession);

		encryptedMessage = newAliceSession.encrypt(MESSAGE3);

		SecureSession bobSession2 = bobChat.loadUpSession(aliceCard, encryptedMessage);
		decryptedMessage = bobSession2.decrypt(encryptedMessage);
		assertEquals("Message should be decrypted properly", MESSAGE3, decryptedMessage);

		try {
			bobChat.loadUpSession(aliceCard, encryptedMessage2);
			fail("Session is removed");
		} catch (VirgilClientException e) {
		}
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
