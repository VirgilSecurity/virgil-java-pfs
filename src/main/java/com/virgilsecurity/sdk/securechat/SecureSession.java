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

import com.virgilsecurity.crypto.VirgilPFS;
import com.virgilsecurity.crypto.VirgilPFSEncryptedMessage;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.securechat.exceptions.NoSessionException;
import com.virgilsecurity.sdk.securechat.model.InitiationMessage;
import com.virgilsecurity.sdk.securechat.model.Message;
import com.virgilsecurity.sdk.securechat.utils.GsonUtils;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public abstract class SecureSession {

    private SecureChatContext context;
    private boolean recovered;
    private byte[] additionalData;
    private SecureChatSessionHelper sessionHelper;
    private Date creationDate;
    private Date expirationDate;
    private VirgilPFS pfs;

    public SecureSession() {
        this.pfs = new VirgilPFS();
    }

    /**
     * Create new instance of {@link SecureSession}.
     * 
     * @param context
     * @param recovered
     * @param additionalData
     * @param sessionHelper
     * @param creationDate
     * @param expirationDate
     */
    public SecureSession(SecureChatContext context, boolean recovered, byte[] additionalData,
            SecureChatSessionHelper sessionHelper, Date creationDate, Date expirationDate) {
        this();
        this.context = context;
        this.recovered = recovered;
        this.additionalData = additionalData;
        this.sessionHelper = sessionHelper;
        this.creationDate = creationDate;
        this.expirationDate = expirationDate;
    }

    public boolean isInitialized() {
        return (this.getPfs().getSession() != null) && (!this.getPfs().getSession().isEmpty());
    }

    public boolean isExpired(Date currentDate) {
        if (this.expirationDate == null) {
            return false;
        }
        return currentDate.after(this.expirationDate);
    }

    public boolean isExpired() {
        return this.isExpired(new Date());
    }

    public String encrypt(String message) throws NoSessionException {
        byte[] messageData = ConvertionUtils.toBytes(message);

        VirgilPFSEncryptedMessage encryptedMessage = this.pfs.encrypt(messageData);

        Message msg = new Message(encryptedMessage.getSessionIdentifier(), encryptedMessage.getSalt(),
                encryptedMessage.getCipherText());

        String msgStr = GsonUtils.getGson().toJson(msg);

        return msgStr;
    }

    public String decrypt(Message encryptedMessage) {
        VirgilPFSEncryptedMessage message = new VirgilPFSEncryptedMessage(encryptedMessage.getSessionId(),
                encryptedMessage.getSalt(), encryptedMessage.getCipherText());

        byte[] msgData = this.pfs.decrypt(message);
        String str = ConvertionUtils.toString(msgData);
        return str;

    }

    public static InitiationMessage extractInitiationMessage(byte[] message) {
        String json = ConvertionUtils.toString(message);
        InitiationMessage msg = GsonUtils.getGson().fromJson(json, InitiationMessage.class);
        return msg;
    }

    public static InitiationMessage extractInitiationMessage(String jsonMessage) {
        InitiationMessage msg = GsonUtils.getGson().fromJson(jsonMessage, InitiationMessage.class);
        return msg;
    }

    public static Message extractMessage(byte[] message) {
        String json = ConvertionUtils.toString(message);
        return extractMessage(json);
    }

    public static Message extractMessage(String jsonMessage) {
        Message msg = GsonUtils.getGson().fromJson(jsonMessage, Message.class);
        return msg;
    }

    public abstract String decrypt(String encryptedMessage) throws NoSessionException, VirgilException;

    public static class CardEntry {
        private String identifier;
        private byte[] publicKeyData;

        /**
         * Create new instance of {@link CardEntry}.
         * 
         * @param identifier
         * @param publicKeyData
         */
        public CardEntry(String identifier, byte[] publicKeyData) {
            super();
            this.identifier = identifier;
            this.publicKeyData = publicKeyData;
        }

        /**
         * @return the identifier
         */
        public String getIdentifier() {
            return identifier;
        }

        /**
         * @param identifier
         *            the identifier to set
         */
        public void setIdentifier(String identifier) {
            this.identifier = identifier;
        }

        /**
         * @return the publicKeyData
         */
        public byte[] getPublicKeyData() {
            return publicKeyData;
        }

        /**
         * @param publicKeyData
         *            the publicKeyData to set
         */
        public void setPublicKeyData(byte[] publicKeyData) {
            this.publicKeyData = publicKeyData;
        }

    }

    /**
     * @return the context
     */
    public SecureChatContext getContext() {
        return context;
    }

    /**
     * @return the additionalData
     */
    public byte[] getAdditionalData() {
        return additionalData;
    }

    /**
     * @return the creationDate
     */
    public Date getCreationDate() {
        return creationDate;
    }

    /**
     * @return the expirationDate
     */
    public Date getExpirationDate() {
        return expirationDate;
    }

    /**
     * @return the recovered
     */
    public boolean isRecovered() {
        return recovered;
    }

    /**
     * @return the sessionHelper
     */
    public SecureChatSessionHelper getSessionHelper() {
        return sessionHelper;
    }

    /**
     * @return the pfs
     */
    public VirgilPFS getPfs() {
        return pfs;
    }

}
