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
package com.virgilsecurity.sdk.securechat.session;

import java.util.Date;

import com.virgilsecurity.crypto.VirgilPFS;
import com.virgilsecurity.crypto.VirgilPFSInitiatorPrivateInfo;
import com.virgilsecurity.crypto.VirgilPFSInitiatorPublicInfo;
import com.virgilsecurity.crypto.VirgilPFSPrivateKey;
import com.virgilsecurity.crypto.VirgilPFSPublicKey;
import com.virgilsecurity.crypto.VirgilPFSResponderPrivateInfo;
import com.virgilsecurity.crypto.VirgilPFSResponderPublicInfo;
import com.virgilsecurity.crypto.VirgilPFSSession;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.securechat.model.CardEntry;

/**
 * @author Andrii Iakovenko
 *
 */
public class SessionInitializer {

	public static class FirstMessageGenerator {

		private byte[] ephPublicKeyData;
		private byte[] ephPublicKeySignature;
		private String identityCardId;
		private String recipientIdCardId;
		private String recipientLtCardId;
		private String recipientOtCardId;

		public FirstMessageGenerator(byte[] ephPublicKeyData, byte[] ephPublicKeySignature, String identityCardId,
				String recipientIdCardId, String recipientLtCardId, String recipientOtCardId) {
			super();
			this.ephPublicKeyData = ephPublicKeyData;
			this.ephPublicKeySignature = ephPublicKeySignature;
			this.identityCardId = identityCardId;
			this.recipientIdCardId = recipientIdCardId;
			this.recipientLtCardId = recipientLtCardId;
			this.recipientOtCardId = recipientOtCardId;
		}

		public String generate(SecureSession secureSession, String message) {
			String firstMessage = secureSession.encryptInitiationMessage(message, this.ephPublicKeyData,
					this.ephPublicKeySignature, this.identityCardId, this.recipientIdCardId, this.recipientLtCardId,
					recipientOtCardId);

			return firstMessage;
		}

	}

	private Crypto crypto;
	private PrivateKey identityPrivateKey;

	private CardModel identityCard;

	/**
	 * @param crypto
	 * @param identityPrivateKey
	 * @param identityCard
	 */
	public SessionInitializer(Crypto crypto, PrivateKey identityPrivateKey, CardModel identityCard) {
		super();
		this.crypto = crypto;
		this.identityPrivateKey = identityPrivateKey;
		this.identityCard = identityCard;
	}

	public SecureSession initializeInitiatorSession(PrivateKey ephPrivateKey, CardEntry recipientIdCard,
			CardEntry recipientLtCard, CardEntry recipientOtCard, byte[] additionalData, Date expirationDate) {
		byte[] privateKeyData = this.crypto.exportPrivateKey(this.identityPrivateKey);
		byte[] ephPrivateKeyData = this.crypto.exportPrivateKey(ephPrivateKey);

		VirgilPFSPrivateKey pfsPrivateKey = new VirgilPFSPrivateKey(privateKeyData);
		VirgilPFSPrivateKey pfsEphPrivateKey = new VirgilPFSPrivateKey(ephPrivateKeyData);

		VirgilPFSInitiatorPrivateInfo initiatorPrivateInfo = new VirgilPFSInitiatorPrivateInfo(pfsPrivateKey,
				pfsEphPrivateKey);

		byte[] responderPublicKeyData = recipientIdCard.getPublicKeyData();
		VirgilPFSPublicKey pfsResponderPublicKey = new VirgilPFSPublicKey(responderPublicKeyData);

		byte[] responderLongTermPublicKeyData = recipientLtCard.getPublicKeyData();
		VirgilPFSPublicKey pfsResponderLongTermPublicKey = new VirgilPFSPublicKey(responderLongTermPublicKeyData);

		VirgilPFSPublicKey pfsResponderOneTimePublicKey = null;
		if (recipientOtCard != null) {
			byte[] responderOneTimePublicKeyData = recipientOtCard.getPublicKeyData();
			pfsResponderOneTimePublicKey = new VirgilPFSPublicKey(responderOneTimePublicKeyData);
		}

		VirgilPFSResponderPublicInfo responderPublicInfo;
		if (pfsResponderOneTimePublicKey == null) {
			responderPublicInfo = new VirgilPFSResponderPublicInfo(pfsResponderPublicKey,
					pfsResponderLongTermPublicKey);
		} else {
			responderPublicInfo = new VirgilPFSResponderPublicInfo(pfsResponderPublicKey, pfsResponderLongTermPublicKey,
					pfsResponderOneTimePublicKey);
		}

		VirgilPFSSession session = null;
		try (VirgilPFS pfs = new VirgilPFS()) {
			if (additionalData == null) {
				session = pfs.startInitiatorSession(initiatorPrivateInfo, responderPublicInfo);
			} else {
				session = pfs.startInitiatorSession(initiatorPrivateInfo, responderPublicInfo, additionalData);
			}
		}

		PublicKey ephPublicKey = this.crypto.extractPublicKey(ephPrivateKey);
		byte[] ephPublicKeyData = this.crypto.exportPublicKey(ephPublicKey);
		byte[] ephPublicKeySignature = this.crypto.sign(ephPublicKeyData, this.identityPrivateKey);

		FirstMessageGenerator firstMessageGenerator = new FirstMessageGenerator(ephPublicKeyData, ephPublicKeySignature,
				this.identityCard.getId(), recipientIdCard.getIdentifier(), recipientLtCard.getIdentifier(),
				recipientOtCard == null ? null : recipientOtCard.getIdentifier());

		SecureSession secureSession = new SecureSession(session, expirationDate, firstMessageGenerator);

		return secureSession;
	}

	public SecureSession initializeResponderSession(CardEntry initiatorCardEntry, PrivateKey privateKey,
			PrivateKey ltPrivateKey, PrivateKey otPrivateKey, byte[] ephPublicKey, byte[] additionalData,
			Date expirationDate) {

		byte[] privateKeyData = this.crypto.exportPrivateKey(this.identityPrivateKey);
		VirgilPFSPrivateKey pfsPrivateKey = new VirgilPFSPrivateKey(privateKeyData);

		byte[] ltPrivateKeyData = this.crypto.exportPrivateKey(ltPrivateKey);
		VirgilPFSPrivateKey pfsLtPrivateKey = new VirgilPFSPrivateKey(ltPrivateKeyData);

		VirgilPFSResponderPrivateInfo responderPrivateInfo = null;
		if (otPrivateKey != null) {
			byte[] otPrivateKeyData = this.crypto.exportPrivateKey(otPrivateKey);
			VirgilPFSPrivateKey pfsOtPrivateKey = new VirgilPFSPrivateKey(otPrivateKeyData);

			responderPrivateInfo = new VirgilPFSResponderPrivateInfo(pfsPrivateKey, pfsLtPrivateKey, pfsOtPrivateKey);
		} else {
			responderPrivateInfo = new VirgilPFSResponderPrivateInfo(pfsPrivateKey, pfsLtPrivateKey);
		}

		VirgilPFSPublicKey initiatorEphPublicKey = new VirgilPFSPublicKey(ephPublicKey);
		VirgilPFSPublicKey initiatorIdPublicKey = new VirgilPFSPublicKey(initiatorCardEntry.getPublicKeyData());

		VirgilPFSInitiatorPublicInfo initiatorPublicInfo = new VirgilPFSInitiatorPublicInfo(initiatorIdPublicKey,
				initiatorEphPublicKey);

		VirgilPFSSession session = null;
		try (VirgilPFS pfs = new VirgilPFS()) {
			if (additionalData == null) {
				session = pfs.startResponderSession(responderPrivateInfo, initiatorPublicInfo);
			} else {
				session = pfs.startResponderSession(responderPrivateInfo, initiatorPublicInfo, additionalData);
			}
		}

		return new SecureSession(session, expirationDate, null);
	}

	public SecureSession initializeSavedSession(byte[] sessionId, byte[] encryptionKey, byte[] decryptionKey,
			byte[] additionalData, Date expirationDate) {
		VirgilPFSSession session = new VirgilPFSSession(sessionId, encryptionKey, decryptionKey, additionalData);

		return new SecureSession(session, expirationDate, null);
	}

}
