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

import com.virgilsecurity.crypto.VirgilPFSEncryptedMessage;
import com.virgilsecurity.crypto.VirgilPFSInitiatorPrivateInfo;
import com.virgilsecurity.crypto.VirgilPFSPrivateKey;
import com.virgilsecurity.crypto.VirgilPFSPublicKey;
import com.virgilsecurity.crypto.VirgilPFSResponderPublicInfo;
import com.virgilsecurity.crypto.VirgilPFSSession;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.securechat.exceptions.NoSessionException;
import com.virgilsecurity.sdk.securechat.model.InitiationMessage;
import com.virgilsecurity.sdk.securechat.model.InitiatorSessionState;
import com.virgilsecurity.sdk.securechat.model.Message;
import com.virgilsecurity.sdk.securechat.utils.GsonUtils;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureSessionInitiator extends SecureSession {

    private CardModel myIdCard;
    private PrivateKey ephPrivateKey;
    private String ephPrivateKeyName;
    private CardEntry recipientIdCard;
    private CardEntry recipientLtCard;
    private CardEntry recipientOtCard;

    public SecureSessionInitiator(SecureChatContext context, SecureChatSessionHelper sessionHelper,
            byte[] additionalData, CardModel myIdCard, PrivateKey ephPrivateKey, String ephPrivateKeyName,
            CardEntry recipientIdCard, CardEntry recipientLtCard, CardEntry recipientOtCard, boolean recovered,
            Date creationDate, Date expirationDate) {
        super(context, recovered, additionalData, sessionHelper, creationDate, expirationDate);
        this.myIdCard = myIdCard;
        this.ephPrivateKey = ephPrivateKey;
        this.ephPrivateKeyName = ephPrivateKeyName;
        this.recipientIdCard = recipientIdCard;
        this.recipientLtCard = recipientLtCard;
        this.recipientOtCard = recipientOtCard;

        if (recovered) {
            this.initiateSession();
        }
    }

    private void initiateSession() {
        byte[] privateKeyData = this.getContext().getCrypto().exportPrivateKey(this.getContext().getPrivateKey());
        byte[] ephPrivateKeyData = this.getContext().getCrypto().exportPrivateKey(this.ephPrivateKey);

        VirgilPFSPrivateKey privateKey = new VirgilPFSPrivateKey(privateKeyData);
        VirgilPFSPrivateKey ephPrivateKey = new VirgilPFSPrivateKey(ephPrivateKeyData);

        VirgilPFSInitiatorPrivateInfo initiatorPrivateInfo = new VirgilPFSInitiatorPrivateInfo(privateKey,
                ephPrivateKey);

        byte[] responderPublicKeyData = this.recipientIdCard.getPublicKeyData();
        VirgilPFSPublicKey responderPublicKey = new VirgilPFSPublicKey(responderPublicKeyData);

        byte[] responderLongTermPublicKeyData = this.recipientLtCard.getPublicKeyData();
        VirgilPFSPublicKey responderLongTermPublicKey = new VirgilPFSPublicKey(responderLongTermPublicKeyData);

        VirgilPFSResponderPublicInfo responderPublicInfo = null;
        if (this.recipientOtCard == null) {
            responderPublicInfo = new VirgilPFSResponderPublicInfo(responderPublicKey, responderLongTermPublicKey);
        } else {
            byte[] responderOneTimePublicKeyData = this.recipientOtCard.getPublicKeyData();
            VirgilPFSPublicKey responderOneTimePublicKey = new VirgilPFSPublicKey(responderOneTimePublicKeyData);
            responderPublicInfo = new VirgilPFSResponderPublicInfo(responderPublicKey, responderLongTermPublicKey,
                    responderOneTimePublicKey);
        }

        VirgilPFSSession session = null;
        if (this.getAdditionalData() == null) {
            session = this.getPfs().startInitiatorSession(initiatorPrivateInfo, responderPublicInfo);
        } else {
            session = this.getPfs().startInitiatorSession(initiatorPrivateInfo, responderPublicInfo, this.getAdditionalData());
        }

        if (!this.isRecovered()) {
            byte[] sessionId = session.getIdentifier();

            InitiatorSessionState sessionState = null;
            if (this.recipientOtCard != null) {
                sessionState = new InitiatorSessionState(sessionId, this.getCreationDate(), this.getExpirationDate(),
                        this.getAdditionalData(), this.ephPrivateKeyName, this.recipientIdCard.getIdentifier(),
                        this.recipientIdCard.getPublicKeyData(), this.recipientLtCard.getIdentifier(),
                        this.recipientLtCard.getPublicKeyData(), this.recipientOtCard.getIdentifier(),
                        this.recipientOtCard.getPublicKeyData());
            } else {
                sessionState = new InitiatorSessionState(sessionId, this.getCreationDate(), this.getExpirationDate(),
                        this.getAdditionalData(), this.ephPrivateKeyName, this.recipientIdCard.getIdentifier(),
                        this.recipientIdCard.getPublicKeyData(), this.recipientLtCard.getIdentifier(),
                        this.recipientLtCard.getPublicKeyData(), null, null);
            }

            this.getSessionHelper().saveSessionState(sessionState, this.recipientIdCard.getIdentifier());
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.securechat.SecureSession#encrypt(java.lang.String)
     */
    @Override
    public String encrypt(String message) throws NoSessionException {
        boolean isFirstMessage = false;
        if (!this.isInitialized()) {
            isFirstMessage = true;
            this.initiateSession();
        }

        if (!this.isInitialized()) {
            throw new NoSessionException("Session is still not initialized.");
        }

        if (isFirstMessage) {
            byte[] messageData = ConvertionUtils.toBytes(message);

            VirgilPFSEncryptedMessage encryptedMessage = this.getPfs().encrypt(messageData);

            Message msg = new Message(encryptedMessage.getSessionIdentifier(), encryptedMessage.getSalt(),
                    encryptedMessage.getCipherText());

            PublicKey ephPublicKey = this.getContext().getCrypto().extractPublicKey(this.ephPrivateKey);
            byte[] ephPublicKeyData = this.getContext().getCrypto().exportPublicKey(ephPublicKey);
            byte[] ephPublicKeySignature = this.getContext().getCrypto().sign(ephPublicKeyData,
                    this.getContext().getPrivateKey());

            InitiationMessage initMsg = null;
            if (this.recipientOtCard != null) {
                initMsg = new InitiationMessage(this.myIdCard.getId(), this.recipientIdCard.getIdentifier(),
                        this.recipientLtCard.getIdentifier(), this.recipientOtCard.getIdentifier(), ephPublicKeyData,
                        ephPublicKeySignature, msg.getSalt(), msg.getCipherText());
            } else {
                initMsg = new InitiationMessage(this.myIdCard.getId(), this.recipientIdCard.getIdentifier(),
                        this.recipientLtCard.getIdentifier(), null, ephPublicKeyData, ephPublicKeySignature,
                        msg.getSalt(), msg.getCipherText());
            }
            String msgStr = GsonUtils.getGson().toJson(initMsg);

            return msgStr;
        } else {
            return super.encrypt(message);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.securechat.SecureSession#decrypt(java.lang.String)
     */
    @Override
    public String decrypt(String encryptedMessage) throws NoSessionException {
        if (!this.isInitialized()) {
            throw new NoSessionException("Session is still not initialized.");
        }
        Message message = SecureSession.extractMessage(encryptedMessage);
        return super.decrypt(message);
    }

}
