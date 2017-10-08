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

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.Fingerprint;
import com.virgilsecurity.sdk.crypto.PublicKey;

/**
 * This Virgil Card validator is used for cards verification ephemeral card
 * vefirication.
 * 
 * @author Andrii Iakovenko
 *
 */
public class EphemeralCardValidator {

	private Crypto crypto;
	private Map<String, PublicKey> verifiers;

	/**
	 * Create new instance of {@link EphemeralCardValidator}.
	 * 
	 * @param crypto
	 *            the {@link Crypto} which is used for crypto operations.
	 */
	public EphemeralCardValidator(Crypto crypto) {
		this.crypto = crypto;
		this.verifiers = new HashMap<>();
	}

	/**
	 * Add new verifier which is used for Virgil Card validation. In common case
	 * it's a Virgil Card identifier and public key pair.
	 * 
	 * @param verifierId
	 *            the verifier's identifier.
	 * @param publicKeyData
	 *            the verifier's public key.
	 */
	public void addVerifier(String verifierId, byte[] publicKeyData) {
		PublicKey publicKey = this.crypto.importPublicKey(publicKeyData);

		this.verifiers.put(verifierId, publicKey);
	}

	/**
	 * Validate Virgil Card.
	 * 
	 * @param card
	 *            the Virgil Card to be validated.
	 * @return {@code true} if card is valid. {@code false} if validation failed
	 *         for some reason.
	 */
	public boolean validate(CardModel card) {
		Fingerprint fingerprint = this.crypto.calculateFingerprint(card.getSnapshot());
		String cardId = fingerprint.toHex();

		if (!cardId.equals(card.getId())) {
			return false;
		}

		for (Entry<String, PublicKey> verifier : this.verifiers.entrySet()) {

			if (!card.getMeta().getSignatures().containsKey(verifier.getKey())) {
				return false;
			}
			byte[] signature = card.getMeta().getSignatures().get(verifier.getKey());
			try {
				return this.crypto.verify(fingerprint.getValue(), signature, verifier.getValue());
			} catch (Exception e) {
				return false;
			}
		}

		return true;
	}

}
