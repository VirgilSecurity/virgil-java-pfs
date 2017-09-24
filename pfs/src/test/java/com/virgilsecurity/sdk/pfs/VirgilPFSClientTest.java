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
package com.virgilsecurity.sdk.pfs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.RequestSigner;
import com.virgilsecurity.sdk.client.VirgilClient;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.pfs.model.RecipientCardsSet;
import com.virgilsecurity.sdk.pfs.model.request.CreateEphemeralCardRequest;
import com.virgilsecurity.sdk.pfs.model.response.BootstrapCardsResponse;
import com.virgilsecurity.sdk.pfs.model.response.OtcCountResponse;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilPFSClientTest extends BaseIT {

    private static final String USERNAME_IDENTITY_TYPE = "username";
    private static final int OTC_COUNT = 5;
    private Crypto crypto;
    private VirgilClient client;
    private VirgilPFSClient pfsClient;
    private RequestSigner requestSigner;
    private PrivateKey appKey;

    private String aliceIdentity;
    private CardModel aliceCard;
    private KeyPair aliceKeys;

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

        client = new VirgilClient(ctx);
        pfsClient = new VirgilPFSClient(ctx);
        requestSigner = new RequestSigner(crypto);

        appKey = crypto.importPrivateKey(APP_PRIVATE_KEY.getBytes(), APP_PRIVATE_KEY_PASSWORD);

        // Create alice card
        aliceIdentity = "alice" + UUID.randomUUID().toString();
        aliceKeys = crypto.generateKeys();
        aliceCard = publishCard("alice", aliceKeys);
    }

    @Test
    public void testFlow() {
        List<RecipientCardsSet> cardsSets = pfsClient.getRecipientCardsSet(Arrays.asList(aliceCard.getId()));
        assertNotNull(cardsSets);
        assertTrue(cardsSets.isEmpty());

        OtcCountResponse otcCount = pfsClient.getOtcCount(aliceCard.getId());
        assertNotNull(otcCount);
        assertEquals(0, otcCount.getActive());

        // Create long time card
        KeyPair ltKeyPair = crypto.generateKeys();
        byte[] publicKeyData = crypto.exportPublicKey(ltKeyPair.getPublicKey());
        CreateEphemeralCardRequest longTimeCardRequest = new CreateEphemeralCardRequest(aliceIdentity,
                USERNAME_IDENTITY_TYPE, publicKeyData);
        requestSigner.authoritySign(longTimeCardRequest, aliceCard.getId(), aliceKeys.getPrivateKey());
        CardModel ltCard = pfsClient.createLongTermCard(aliceCard.getId(), longTimeCardRequest);
        assertNotNull(ltCard);
        assertNotNull(ltCard.getId());

        // Verify ephemeral cards
        cardsSets = pfsClient.getRecipientCardsSet(Arrays.asList(aliceCard.getId()));
        assertNotNull(cardsSets);
        assertFalse(cardsSets.isEmpty());
        assertEquals(1, cardsSets.size());

        RecipientCardsSet cardsSet = cardsSets.get(0);
        assertNotNull(cardsSet);
        assertNotNull(cardsSet.getLongTermCard());
        assertNotNull(cardsSet.getLongTermCard().getId());
        assertEquals(ltCard.getId(), cardsSet.getLongTermCard().getId());
        assertNull(cardsSet.getOneTimeCard());

        // Create one time cards
        List<KeyPair> otKeyPairs = new ArrayList<>();
        for (int i = 0; i < OTC_COUNT; i++) {
            otKeyPairs.add(crypto.generateKeys());
        }
        List<CreateEphemeralCardRequest> oneTimeCardRequests = new ArrayList<>();
        for (KeyPair keyPair : otKeyPairs) {
            publicKeyData = crypto.exportPublicKey(keyPair.getPublicKey());
            CreateEphemeralCardRequest oneTimeCardRequest = new CreateEphemeralCardRequest(aliceIdentity,
                    USERNAME_IDENTITY_TYPE, publicKeyData);
            requestSigner.authoritySign(oneTimeCardRequest, aliceCard.getId(), aliceKeys.getPrivateKey());
            oneTimeCardRequests.add(oneTimeCardRequest);
        }
        List<CardModel> otCards = pfsClient.createOneTimeCards(aliceCard.getId(), oneTimeCardRequests);
        assertNotNull(otCards);
        assertFalse(otCards.isEmpty());
        assertEquals(OTC_COUNT, otCards.size());

        // Verify one time cards
        cardsSets = pfsClient.getRecipientCardsSet(Arrays.asList(aliceCard.getId()));
        assertNotNull(cardsSets);
        assertFalse(cardsSets.isEmpty());
        assertEquals(1, cardsSets.size());

        for (RecipientCardsSet cardSet : cardsSets) {
            assertNotNull(cardSet);

            assertNotNull(cardSet.getIdentityCard());
            assertNotNull(cardSet.getIdentityCard().getId());
            assertEquals(aliceCard.getId(), cardSet.getIdentityCard().getId());

            assertNotNull(cardSet.getLongTermCard());
            assertNotNull(cardSet.getLongTermCard().getId());
            assertEquals(ltCard.getId(), cardSet.getLongTermCard().getId());

            assertNotNull(cardSet.getOneTimeCard());
            assertNotNull(cardSet.getOneTimeCard().getId());
        }

        // Validate one time cards
        List<String> otCardIds = new ArrayList<>();
        for (CardModel otCard : otCards) {
            otCardIds.add(otCard.getId());
        }
        List<String> validatedOtCards = pfsClient.validateOneTimeCards(aliceCard.getId(), otCardIds);
        assertNotNull(validatedOtCards);
        assertFalse(validatedOtCards.isEmpty());

        // Get credentials
        cardsSets = pfsClient.getRecipientCardsSet(Arrays.asList(aliceCard.getId()));
        assertNotNull(cardsSets);
        assertFalse(cardsSets.isEmpty());
        assertEquals(1, cardsSets.size());

        // Validate one time cards (no cards left)
        otCardIds = new ArrayList<>();
        for (CardModel otCard : otCards) {
            otCardIds.add(otCard.getId());
        }
        validatedOtCards = pfsClient.validateOneTimeCards(aliceCard.getId(), otCardIds);
        assertNotNull(validatedOtCards);
        assertFalse(validatedOtCards.isEmpty());
    }

    @Test
    public void test_bootstrapCardsSet() {
        List<RecipientCardsSet> cardsSets = pfsClient.getRecipientCardsSet(Arrays.asList(aliceCard.getId()));
        assertNotNull(cardsSets);
        assertTrue(cardsSets.isEmpty());

        OtcCountResponse otcCount = pfsClient.getOtcCount(aliceCard.getId());
        assertNotNull(otcCount);
        assertEquals(0, otcCount.getActive());

        // Create long time card request
        KeyPair ltKeyPair = crypto.generateKeys();
        byte[] publicKeyData = crypto.exportPublicKey(ltKeyPair.getPublicKey());
        CreateEphemeralCardRequest longTimeCardRequest = new CreateEphemeralCardRequest(aliceIdentity,
                USERNAME_IDENTITY_TYPE, publicKeyData);
        requestSigner.authoritySign(longTimeCardRequest, aliceCard.getId(), aliceKeys.getPrivateKey());

        // Create one time card requests
        List<KeyPair> otKeyPairs = new ArrayList<>();
        for (int i = 0; i < OTC_COUNT; i++) {
            otKeyPairs.add(crypto.generateKeys());
        }
        List<CreateEphemeralCardRequest> oneTimeCardRequests = new ArrayList<>();
        for (KeyPair keyPair : otKeyPairs) {
            publicKeyData = crypto.exportPublicKey(keyPair.getPublicKey());
            CreateEphemeralCardRequest oneTimeCardRequest = new CreateEphemeralCardRequest(aliceIdentity,
                    USERNAME_IDENTITY_TYPE, publicKeyData);
            requestSigner.authoritySign(oneTimeCardRequest, aliceCard.getId(), aliceKeys.getPrivateKey());
            oneTimeCardRequests.add(oneTimeCardRequest);
        }

        BootstrapCardsResponse cardsResponse = pfsClient.bootstrapCardsSet(aliceCard.getId(), longTimeCardRequest,
                oneTimeCardRequests);
        assertNotNull(cardsResponse);

        assertNotNull(cardsResponse.getLongTimeCard());
        assertEquals(aliceIdentity, cardsResponse.getLongTimeCard().getSnapshotModel().getIdentity());
        assertNotNull(cardsResponse.getOneTimeCards());
        assertEquals(OTC_COUNT, cardsResponse.getOneTimeCards().size());
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
