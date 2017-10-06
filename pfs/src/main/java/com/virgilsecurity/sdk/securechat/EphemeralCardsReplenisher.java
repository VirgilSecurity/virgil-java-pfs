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

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.logging.Logger;

import com.virgilsecurity.sdk.client.RequestSigner;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.pfs.VirgilPFSClient;
import com.virgilsecurity.sdk.pfs.model.request.CreateEphemeralCardRequest;
import com.virgilsecurity.sdk.securechat.KeyStorageManager.HelperKeyEntry;

/**
 * @author Andrii Iakovenko
 *
 */
public class EphemeralCardsReplenisher {
	private static final Logger log = Logger.getLogger(EphemeralCardsReplenisher.class.getName());
	public static final String IDENTITY_TYPE = "identity_card_id";

	private Crypto crypto;
	private PrivateKey identityPrivateKey;
	private String identityCardId;
	private VirgilPFSClient client;
	private KeyStorageManager keyStorageManager;

	/**
	 * Create new instance of EphemeralCardsReplenisher.
	 * 
	 * @param crypto
	 *            the {@link Crypto}
	 * @param identityPrivateKey
	 *            the identity private key.
	 * @param identityCardId
	 *            the identity Virgil Card identifier.
	 * @param client
	 *            the {@link VirgilPFSClient}.
	 * @param keyStorageManager
	 *            the key storage manager.
	 */
	public EphemeralCardsReplenisher(Crypto crypto, PrivateKey identityPrivateKey, String identityCardId,
			VirgilPFSClient client, KeyStorageManager keyStorageManager) {
		this.crypto = crypto;
		this.identityPrivateKey = identityPrivateKey;
		this.identityCardId = identityCardId;
		this.client = client;
		this.keyStorageManager = keyStorageManager;
	}

	/**
	 * Add new cards if needed.
	 * 
	 * @param includeLtcCard
	 *            if set to {@code true}, that long time card will be created if
	 *            the is no one.
	 * @param numberOfOtcCards
	 *            the number of one-time cards which is should be available at
	 *            the moment.
	 */
	public void addCards(boolean includeLtcCard, int numberOfOtcCards) {
		log.fine(String.format("Adding %d cards for: %s, include lt: %b", numberOfOtcCards, this.identityCardId,
				includeLtcCard));

		List<KeyStorageManager.HelperKeyEntry> otcKeys = new ArrayList<>(numberOfOtcCards);
		List<CreateEphemeralCardRequest> otcCardsRequests = new ArrayList<>(numberOfOtcCards);

		for (int i = 0; i < numberOfOtcCards; i++) {
			KeyPair keyPair = crypto.generateKeys();

			Entry<CreateEphemeralCardRequest, String> entry = generateRequest(keyPair, false);
			otcCardsRequests.add(entry.getKey());

			HelperKeyEntry keyEntry = new KeyStorageManager.HelperKeyEntry(keyPair.getPrivateKey(), entry.getValue());
			otcKeys.add(keyEntry);
		}

		KeyStorageManager.HelperKeyEntry ltcKey = null;
		CreateEphemeralCardRequest ltcCardRequest = null;
		if (includeLtcCard) {
			KeyPair keyPair = this.crypto.generateKeys();
			Entry<CreateEphemeralCardRequest, String> entry = generateRequest(keyPair, true);
			ltcCardRequest = entry.getKey();

			ltcKey = new KeyStorageManager.HelperKeyEntry(keyPair.getPrivateKey(), entry.getValue());
		}

		this.keyStorageManager.saveKeys(otcKeys, ltcKey);

		// TODO extend exception handling

		if (ltcCardRequest != null) {
			this.client.bootstrapCardsSet(this.identityCardId, ltcCardRequest, otcCardsRequests);
		} else if (!otcCardsRequests.isEmpty()) {
			this.client.createOneTimeCards(this.identityCardId, otcCardsRequests);
		}
	}

	private Entry<CreateEphemeralCardRequest, String> generateRequest(KeyPair keyPair, boolean isLtc) {
		String identity = this.identityCardId;

		byte[] publicKeyData = this.crypto.exportPublicKey(keyPair.getPublicKey());
		CreateEphemeralCardRequest request = new CreateEphemeralCardRequest(identity, IDENTITY_TYPE, publicKeyData);

		RequestSigner requestSigner = new RequestSigner(this.crypto);
		String cardId = requestSigner.getCardId(request);
		requestSigner.authoritySign(request, this.identityCardId, this.identityPrivateKey);

		return new AbstractMap.SimpleEntry<CreateEphemeralCardRequest, String>(request, cardId);
	}
}
