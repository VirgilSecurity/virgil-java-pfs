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
import com.virgilsecurity.sdk.securechat.keystorage.KeyStorage;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChatContext {

	private CardModel identityCard;
	private PrivateKey identityPrivateKey;
	private Crypto crypto;
	private KeyStorage keyStorage;
	private VirgilPFSClientContext context;
	private DeviceManager deviceManager;
	private UserDataStorage userDataStorage;

	/* Long term key time to live in seconds */
	private int longTermKeysTtl;

	/*
	 * Expired long-term keys time-to-live in seconds (time during which expired
	 * long-term key is not removed)
	 */
	private int expiredLongTermKeysTtl;

	/* Session time to live in seconds */
	private int sessionTtl;

	/*
	 * Expired session time-to-live in seconds (time during which expired
	 * session key is not removed)
	 */
	public int expiredSessionTtl;

	/*
	 * Exhausted one-time keys time-to-live in seconds (time during which
	 * one-time is not removed after sdk determined that it was exhausted)
	 */
	public int exhaustedOneTimeKeysTtl;

	/**
	 * Create new instance of {@link SecureChatContext}.
	 */
	public SecureChatContext() {
		longTermKeysTtl = 60 * 60 * 24 * 7; // One week
		expiredLongTermKeysTtl = 60 * 60 * 24; // One day
		sessionTtl = 24 * 60 * 60; // One day
		expiredSessionTtl = 60 * 60 * 24; // One day
		exhaustedOneTimeKeysTtl = 60 * 60 * 24; // One day
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
		this.identityPrivateKey = myPrivateKey;
		this.crypto = crypto;
		this.context = new VirgilPFSClientContext(accessToken);
	}

	public SecureChatContext(CardModel myIdentityCard, PrivateKey myPrivateKey, Crypto crypto,
			VirgilPFSClientContext context) {
		this();
		this.identityCard = myIdentityCard;
		this.identityPrivateKey = myPrivateKey;
		this.crypto = crypto;
		this.context = context;
	}

	/**
	 * @return the context
	 */
	public VirgilPFSClientContext getContext() {
		return context;
	}

	/**
	 * @return the crypto
	 */
	public Crypto getCrypto() {
		return crypto;
	}

	/**
	 * @return the deviceManager
	 */
	public DeviceManager getDeviceManager() {
		return deviceManager;
	}

	/**
	 * @return the exhaustedOneTimeKeysTtl
	 */
	public int getExhaustedOneTimeKeysTtl() {
		return exhaustedOneTimeKeysTtl;
	}

	/**
	 * @return the expiredLongTermKeysTtl
	 */
	public int getExpiredLongTermKeysTtl() {
		return expiredLongTermKeysTtl;
	}

	/**
	 * @return the expiredSessionTtl
	 */
	public int getExpiredSessionTtl() {
		return expiredSessionTtl;
	}

	/**
	 * Returns user's identity card.
	 * 
	 * @return the identityCard
	 */
	public CardModel getIdentityCard() {
		return identityCard;
	}

	/**
	 * Returns user's private key that corresponds to his identity card on
	 * Virgil Cards Service.
	 * 
	 * @return the identityPrivateKey
	 */
	public PrivateKey getIdentityPrivateKey() {
		return identityPrivateKey;
	}

	/**
	 * KeyStorage implementation used to store private/symmetric keys needed for
	 * PFS (default is JsonFileKeyStorage).
	 * 
	 * @return the keyStorage
	 */
	public KeyStorage getKeyStorage() {
		return keyStorage;
	}

	/**
	 * @return the longTermKeysTtl
	 */
	public int getLongTermKeysTtl() {
		return longTermKeysTtl;
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
	 * @return the user data storage.
	 */
	public UserDataStorage getUserDataStorage() {
		return userDataStorage;
	}

	/**
	 * @param context
	 *            the context to set
	 */
	public void setContext(VirgilPFSClientContext context) {
		this.context = context;
	}

	/**
	 * @param crypto
	 *            the crypto to set
	 */
	public void setCrypto(Crypto crypto) {
		this.crypto = crypto;
	}

	/**
	 * @param deviceManager
	 *            the deviceManager to set
	 */
	public void setDeviceManager(DeviceManager deviceManager) {
		this.deviceManager = deviceManager;
	}

	/**
	 * @param exhaustedOneTimeKeysTtl
	 *            the exhaustedOneTimeKeysTtl to set
	 */
	public void setExhaustedOneTimeKeysTtl(int exhaustedOneTimeKeysTtl) {
		this.exhaustedOneTimeKeysTtl = exhaustedOneTimeKeysTtl;
	}

	/**
	 * @param expiredLongTermKeysTtl
	 *            the expiredLongTermKeysTtl to set
	 */
	public void setExpiredLongTermKeysTtl(int expiredLongTermKeysTtl) {
		this.expiredLongTermKeysTtl = expiredLongTermKeysTtl;
	}

	/**
	 * @param expiredSessionTtl
	 *            the expiredSessionTtl to set
	 */
	public void setExpiredSessionTtl(int expiredSessionTtl) {
		this.expiredSessionTtl = expiredSessionTtl;
	}

	/**
	 * @param identityCard
	 *            the myIdentityCard to set
	 */
	public void setIdentityCard(CardModel identityCard) {
		this.identityCard = identityCard;
	}

	/**
	 * @param privateKey
	 *            the privateKey to set
	 */
	public void setIdentityPrivateKey(PrivateKey privateKey) {
		this.identityPrivateKey = privateKey;
	}

	/**
	 * @param keyStorage
	 *            the keyStorage to set
	 */
	public void setKeyStorage(KeyStorage keyStorage) {
		this.keyStorage = keyStorage;
	}

	/**
	 * @param longTermKeysTtl
	 *            the longTermKeysTtl to set
	 */
	public void setLongTermKeysTtl(int longTermKeysTtl) {
		this.longTermKeysTtl = longTermKeysTtl;
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
	 * @param userDataStorage
	 *            the user data storage.
	 */
	public void setUserDataStorage(UserDataStorage userDataStorage) {
		this.userDataStorage = userDataStorage;
	}

}
