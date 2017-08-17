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

import java.util.Date;

import com.virgilsecurity.crypto.VirgilPFSInitiatorPublicInfo;
import com.virgilsecurity.crypto.VirgilPFSPrivateKey;
import com.virgilsecurity.crypto.VirgilPFSPublicKey;
import com.virgilsecurity.crypto.VirgilPFSResponderPrivateInfo;
import com.virgilsecurity.crypto.VirgilPFSSession;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.securechat.exceptions.NoSessionException;
import com.virgilsecurity.sdk.securechat.model.InitiationMessage;
import com.virgilsecurity.sdk.securechat.model.Message;
import com.virgilsecurity.sdk.securechat.model.ResponderSessionState;
import com.virgilsecurity.sdk.securechat.utils.SessionStateResolver;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureSessionResponder extends SecureSession {

    private SecureChatKeyHelper secureChatKeyHelper;
    public CardEntry initiatorIdCard;

    public SecureSessionResponder(SecureChatContext context, SecureChatSessionHelper sessionHelper,
            byte[] additionalData, SecureChatKeyHelper secureChatKeyHelper, CardEntry initiatorIdCard,
            byte[] ephPublicKeyData, String receiverLtcId, String receiverOtcId, Date creationDate,
            Date expirationDate) throws CryptoException {
        super(context, true, additionalData, sessionHelper, creationDate, expirationDate);
        this.secureChatKeyHelper = secureChatKeyHelper;
        this.initiatorIdCard = initiatorIdCard;

        this.initiateSession(ephPublicKeyData, receiverLtcId, receiverOtcId);
    }

    public SecureSessionResponder(SecureChatContext context, SecureChatSessionHelper sessionHelper,
            byte[] additionalData, SecureChatKeyHelper secureChatKeyHelper, CardEntry initiatorCardEntry,
            Date creationDate, Date expirationDate) {
        super(context, false, additionalData, sessionHelper, creationDate, expirationDate);
        this.initiatorIdCard = initiatorCardEntry;
        this.secureChatKeyHelper = secureChatKeyHelper;

    }

    private void initiateSession(InitiationMessage initiationMessage) throws VirgilException {
        PublicKey initiatorPublicKey = this.getContext().getCrypto()
                .importPublicKey(this.initiatorIdCard.getPublicKeyData());
        try {
            this.getContext().getCrypto().verify(initiationMessage.getEphPublicKey(),
                    initiationMessage.getEphPublicKeySignature(), initiatorPublicKey);
        } catch (VerificationException e) {
            throw new VirgilException("Error validating initiator signature.");
        }

        if (!initiationMessage.getInitiatorIcId().equals(this.initiatorIdCard.getIdentifier())) {
            throw new VirgilException(
                    "Initiator identity card id for this session and InitiationMessage doesn't match.");
        }

        this.initiateSession(initiationMessage.getEphPublicKey(), initiationMessage.getResponderLtcId(),
                initiationMessage.getResponderOtcId());
    }

    private void initiateSession(byte[] ephPublicKeyData, String receiverLtcId, String receiverOtcId) throws CryptoException {
        byte[] privateKeyData = this.getContext().getCrypto().exportPrivateKey(this.getContext().getPrivateKey());
        VirgilPFSPrivateKey privateKey = new VirgilPFSPrivateKey(privateKeyData);

        PrivateKey myLtPrivateKey = this.secureChatKeyHelper.getLtPrivateKey(receiverLtcId);
        byte[] ltPrivateKeyData = this.getContext().getCrypto().exportPrivateKey(myLtPrivateKey);
        VirgilPFSPrivateKey ltPrivateKey = new VirgilPFSPrivateKey(ltPrivateKeyData);

        PrivateKey myOtPrivateKey = null;
        byte[] otPrivateKeyData = null;
        VirgilPFSResponderPrivateInfo responderPrivateInfo;
        if (receiverOtcId == null) {
            responderPrivateInfo = new VirgilPFSResponderPrivateInfo(privateKey, ltPrivateKey);
        } else {
            myOtPrivateKey = this.secureChatKeyHelper.getOtPrivateKey(receiverOtcId);
            otPrivateKeyData = this.getContext().getCrypto().exportPrivateKey(myOtPrivateKey);
            VirgilPFSPrivateKey otPrivateKey = new VirgilPFSPrivateKey(otPrivateKeyData);

            responderPrivateInfo = new VirgilPFSResponderPrivateInfo(privateKey, ltPrivateKey, otPrivateKey);
        }

        VirgilPFSPublicKey initiatorEphPublicKey = new VirgilPFSPublicKey(ephPublicKeyData);
        VirgilPFSPublicKey initiatorIdPublicKey = new VirgilPFSPublicKey(this.initiatorIdCard.getPublicKeyData());
        VirgilPFSInitiatorPublicInfo initiatorPublicInfo = new VirgilPFSInitiatorPublicInfo(initiatorIdPublicKey,
                initiatorEphPublicKey);

        VirgilPFSSession session;
        if (this.getAdditionalData() == null) {
            session = this.getPfs().startResponderSession(responderPrivateInfo, initiatorPublicInfo);
        } else {
            session = this.getPfs().startResponderSession(responderPrivateInfo, initiatorPublicInfo,
                    this.getAdditionalData());
        }

        if (!this.isRecovered()) {
            byte[] sessionId = session.getIdentifier();
            ResponderSessionState sessionState = new ResponderSessionState(sessionId, this.getCreationDate(),
                    this.getExpirationDate(), this.getAdditionalData(), ephPublicKeyData,
                    this.initiatorIdCard.getIdentifier(), this.initiatorIdCard.getPublicKeyData(), receiverLtcId,
                    receiverOtcId);
            this.getSessionHelper().saveSessionState(sessionState, this.initiatorIdCard.getIdentifier());
        }
    }

    public String encrypt(String message) throws NoSessionException {
        if (!this.isInitialized()) {
            throw new NoSessionException("Session is still not initialized.");
        }

        return super.encrypt(message);
    }

    public String decrypt(InitiationMessage initiationMessage) throws VirgilException {
        if (!this.isInitialized()) {
            this.initiateSession(initiationMessage);
        }

        if (!this.isInitialized()) {
            throw new VirgilException("Session is still not initialized.");
        }

        if (this.getPfs().getSession() == null) {
            throw new VirgilException("Session id is missing.");
        }
        byte[] sessionId = this.getPfs().getSession().getIdentifier();

        Message message = new Message(sessionId, initiationMessage.getSalt(), initiationMessage.getCipherText());

        return this.decrypt(message);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.securechat.SecureSession#decrypt(java.lang.String)
     */
    @Override
    public String decrypt(String encryptedMessage) throws VirgilException {
        if (SessionStateResolver.isInitiationMessage(encryptedMessage)) {

            InitiationMessage initiationMessage = SecureSession.extractInitiationMessage(encryptedMessage);
            return this.decrypt(initiationMessage);
        } else {
            if (!this.isInitialized()) {
                throw new NoSessionException("Session is still not initialized.");
            }
            Message msg = SecureSession.extractMessage(encryptedMessage);
            return super.decrypt(msg);
        }
    }

}
