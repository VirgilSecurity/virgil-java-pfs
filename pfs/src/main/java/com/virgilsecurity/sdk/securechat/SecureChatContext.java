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

import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.device.DeviceManager;
import com.virgilsecurity.sdk.pfs.VirgilPFSClientContext;
import com.virgilsecurity.sdk.storage.KeyStorage;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChatContext {

    private CardModel identityCard;
    private PrivateKey privateKey;
    private Crypto crypto;
    private KeyStorage keyStorage;
    private VirgilPFSClientContext context;
    private DeviceManager deviceManager;
    private UserDataStorage userDefaults;

    /* Long term key time to live in seconds */
    private int longTermKeysTtl;

    /* Session time to live in seconds */
    private int sessionTtl;

    /**
     * Create new instance of {@link SecureChatContext}.
     */
    public SecureChatContext() {
        longTermKeysTtl = 7 * 24 * 60 * 60; // One week
        sessionTtl = 24 * 60 * 60; // One day
    }

    public SecureChatContext(CardModel myIdentityCard, PrivateKey myPrivateKey, Crypto crypto,
            VirgilPFSClientContext context) {
        this();
        this.identityCard = myIdentityCard;
        this.privateKey = myPrivateKey;
        this.crypto = crypto;
        this.context = context;
    }

    /**
     * Create new instance of {@link SecureChatContext}.
     * 
     * @param myIdentityCard
     * @param myPrivateKey
     * @param crypto
     */
    public SecureChatContext(CardModel myIdentityCard, PrivateKey myPrivateKey, Crypto crypto, String accessToken) {
        this();
        this.identityCard = myIdentityCard;
        this.privateKey = myPrivateKey;
        this.crypto = crypto;
        this.context = new VirgilPFSClientContext(accessToken);
    }

    /**
     * @return the identityCard
     */
    public CardModel getIdentityCard() {
        return identityCard;
    }

    /**
     * @param identityCard
     *            the myIdentityCard to set
     */
    public void setIdentityCard(CardModel identityCard) {
        this.identityCard = identityCard;
    }

    /**
     * @return the privateKey
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * @param privateKey
     *            the privateKey to set
     */
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * @return the crypto
     */
    public Crypto getCrypto() {
        return crypto;
    }

    /**
     * @param crypto
     *            the crypto to set
     */
    public void setCrypto(Crypto crypto) {
        this.crypto = crypto;
    }

    /**
     * @return the keyStorage
     */
    public KeyStorage getKeyStorage() {
        return keyStorage;
    }

    /**
     * @param keyStorage
     *            the keyStorage to set
     */
    public void setKeyStorage(KeyStorage keyStorage) {
        this.keyStorage = keyStorage;
    }

    /**
     * @return the context
     */
    public VirgilPFSClientContext getContext() {
        return context;
    }

    /**
     * @param context
     *            the context to set
     */
    public void setContext(VirgilPFSClientContext context) {
        this.context = context;
    }

    /**
     * @return the deviceManager
     */
    public DeviceManager getDeviceManager() {
        return deviceManager;
    }

    /**
     * @param deviceManager
     *            the deviceManager to set
     */
    public void setDeviceManager(DeviceManager deviceManager) {
        this.deviceManager = deviceManager;
    }

    /**
     * @return the longTermKeysTtl
     */
    public int getLongTermKeysTtl() {
        return longTermKeysTtl;
    }

    /**
     * @param longTermKeysTtl
     *            the longTermKeysTtl to set
     */
    public void setLongTermKeysTtl(int longTermKeysTtl) {
        this.longTermKeysTtl = longTermKeysTtl;
    }

    /**
     * Get session time to live in seconds.
     * 
     * @return the session TTL.
     */
    public int getSessionTtl() {
        return sessionTtl;
    }

    /**
     * Set session time to live in seconds.
     * 
     * @param sessionTtl
     *            the session TTL.
     */
    public void setSessionTtl(int sessionTtl) {
        this.sessionTtl = sessionTtl;
    }

    /**
     * @return the userDefaults
     */
    public UserDataStorage getUserDefaults() {
        return userDefaults;
    }

    /**
     * @param userDefaults
     *            the userDefaults to set
     */
    public void setUserDefaults(UserDataStorage userDefaults) {
        this.userDefaults = userDefaults;
    }

}
