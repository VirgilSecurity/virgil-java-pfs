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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.CardValidator;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.device.DefaultDeviceManager;
import com.virgilsecurity.sdk.highlevel.AppCredentials;
import com.virgilsecurity.sdk.highlevel.VirgilApi;
import com.virgilsecurity.sdk.highlevel.VirgilApiContext;
import com.virgilsecurity.sdk.highlevel.VirgilApiImpl;
import com.virgilsecurity.sdk.highlevel.VirgilBuffer;
import com.virgilsecurity.sdk.highlevel.VirgilCard;
import com.virgilsecurity.sdk.highlevel.VirgilKey;
import com.virgilsecurity.sdk.pfs.BaseIT;
import com.virgilsecurity.sdk.pfs.VirgilPFSClientContext;
import com.virgilsecurity.sdk.securechat.impl.DefaultUserDataStorage;
import com.virgilsecurity.sdk.securechat.utils.SessionStateResolver;
import com.virgilsecurity.sdk.storage.DefaultKeyStorage;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChatHiLevelTest extends BaseIT {

    private static final String USERNAME_IDENTITY_TYPE = "username";

    private VirgilApi virgilApi;

    private String aliceIdentity;
    private String bobIdentity;

    private VirgilCard aliceCard;
    private VirgilCard bobCard;

    private VirgilKey aliceKey;
    private VirgilKey bobKey;

    private SecureChatContext aliceChatContext;
    private SecureChatContext bobChatContext;

    private SecureChat aliceChat;
    private SecureChat bobChat;

    @Before
    public void setUp() throws MalformedURLException, VirgilException {
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

        // Initialize Hi-Level api
        AppCredentials credentials = new AppCredentials();
        credentials.setAppId(APP_ID);
        credentials.setAppKey(VirgilBuffer.from(APP_PRIVATE_KEY));
        credentials.setAppKeyPassword(APP_PRIVATE_KEY_PASSWORD);

        VirgilApiContext context = new VirgilApiContext(APP_TOKEN);
        context.setCredentials(credentials);
        context.setClientContext(ctx);

        virgilApi = new VirgilApiImpl(context);

        // For tests only
        context.getClient().setCardValidator(new CardValidator() {

            @Override
            public boolean validate(CardModel card) {
                return true;
            }
        });

        // Create alice card
        aliceIdentity = "alice" + UUID.randomUUID().toString();
        bobIdentity = "bob" + UUID.randomUUID().toString();

        aliceKey = virgilApi.getKeys().generate();
        aliceCard = virgilApi.getCards().create(aliceIdentity, aliceKey, USERNAME_IDENTITY_TYPE).publish();

        bobKey = virgilApi.getKeys().generate();
        bobCard = virgilApi.getCards().create(bobIdentity, bobKey, USERNAME_IDENTITY_TYPE).publish();

        aliceChatContext = new SecureChatContext(aliceCard.getModel(), aliceKey.getPrivateKey(), context.getCrypto(),
                ctx);
        aliceChatContext.setKeyStorage(new DefaultKeyStorage(System.getProperty("java.io.tmpdir"), aliceIdentity));
        aliceChatContext.setDeviceManager(new DefaultDeviceManager());
        aliceChatContext.setUserDefaults(new DefaultUserDataStorage());
        aliceChat = new SecureChat(aliceChatContext);

        bobChatContext = new SecureChatContext(bobCard.getModel(), bobKey.getPrivateKey(), context.getCrypto(), ctx);
        bobChatContext.setKeyStorage(new DefaultKeyStorage(System.getProperty("java.io.tmpdir"), aliceIdentity));
        bobChatContext.setDeviceManager(new DefaultDeviceManager());
        bobChatContext.setUserDefaults(new DefaultUserDataStorage());
        bobChat = new SecureChat(bobChatContext);
    }

    @Test
    public void aliceToBobFlow() throws VirgilException {
        aliceChat.rotateKeys(5);
        bobChat.rotateKeys(5);

        SecureSession aliceSession = aliceChat.activeSession(bobCard.getId());
        assertNull("No active session yet", aliceSession);

        /** Start new session */
        aliceSession = aliceChat.startNewSession(bobCard.getModel(), null);
        assertNotNull("New session started", aliceSession);
        assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));

        /** Send first message to Bob */
        String firstMessage = UUID.randomUUID().toString();
        String encryptedFirstMessage = aliceSession.encrypt(firstMessage);
        assertNotNull(encryptedFirstMessage);
        assertTrue(SessionStateResolver.isInitiationMessage(encryptedFirstMessage));

        // Bob receives message and create session
        SecureSession bobSession = bobChat.loadUpSession(aliceCard.getModel(), encryptedFirstMessage);
        assertNotNull(bobSession);
        assertThat("Bob is responder", bobSession, instanceOf(SecureSessionResponder.class));
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
        aliceSession = aliceChat.loadUpSession(bobCard.getModel(), encryptedMessage);
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
        bobSession = bobChat.loadUpSession(aliceCard.getModel(), encryptedMessage);
        assertNotNull(bobSession);
        assertThat("Alice is initiator", bobSession, instanceOf(SecureSessionResponder.class));

        /** Expire Alices's session */

        /** Expire Bob's session */

        /** Expire long term card */
    }

}
