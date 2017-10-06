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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.securechat.keystorage.KeyAttrs;
import com.virgilsecurity.sdk.securechat.keystorage.KeyStorage;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.VirgilKeyEntry;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * Use {@linkplain KeyStorageManager} to store your private keys.
 * 
 * @author Andrii Iakovenko
 *
 */
public class KeyStorageManager {

	public static class HelperKeyEntry {
		private PrivateKey privateKey;
		String name;

		/**
		 * Create new instance of HelperKeyEntry.
		 */
		public HelperKeyEntry() {
		}

		/**
		 * Create new instance of {@link HelperKeyEntry}.
		 * 
		 * @param privateKey
		 *            the private key.
		 * @param name
		 *            the private key name.
		 */
		public HelperKeyEntry(PrivateKey privateKey, String name) {
			this.privateKey = privateKey;
			this.name = name;
		}

		/**
		 * @return the key name.
		 */
		public String getName() {
			return name;
		}

		/**
		 * @return the private key.
		 */
		public PrivateKey getPrivateKey() {
			return privateKey;
		}

		/**
		 * @param name
		 *            the name to set.
		 */
		public void setName(String name) {
			this.name = name;
		}

		/**
		 * @param privateKey
		 *            the private key to set.
		 */
		public void setPrivateKey(PrivateKey privateKey) {
			this.privateKey = privateKey;
		}

	}

	/**
	 * This us utils class which should be used when you manipulate of key
	 * names.
	 * 
	 * @author Andrii Iakovenko
	 *
	 */
	public static class KeyNamesHelper {
		private static final String OtPrefix = "OT_KEY";
		private static final String LtPrefix = "LT_KEY";
		private static final String SessPrefix = "SESS_KEYS";

		private String identityCardId;

		/**
		 * Create new instance of {@link KeyNamesHelper}.
		 * 
		 * @param identityCardId
		 *            the identify card identifier.
		 */
		public KeyNamesHelper(String identityCardId) {
			this.identityCardId = identityCardId;
		}

		String extractLTCardId(String keyEntryName) {
			String prefix = String.format("%s.%s.", this.getPrivateKeyEntryHeader(), LtPrefix);
			return keyEntryName.replace(prefix, "");
		}

		String extractOTCardId(String keyEntryName) {
			String prefix = String.format("%s.%s.", this.getPrivateKeyEntryHeader(), OtPrefix);
			return keyEntryName.replace(prefix, "");
		}

		byte[] extractSessionId(String keyEntryName) {
			String prefix = String.format("%s.%s.", this.getPrivateKeyEntryHeader(), SessPrefix);
			String id = keyEntryName.replace(prefix, "");
			return ConvertionUtils.base64ToBytes(id);
		}

		String getLtPrivateKeyEntryName(String name) {
			return String.format("%s.%s.%s", this.getPrivateKeyEntryHeader(), LtPrefix, name);
		}

		String getOtPrivateKeyEntryName(String name) {
			return String.format("%s.%s.%s", this.getPrivateKeyEntryHeader(), OtPrefix, name);
		}

		private String getPrivateKeyEntryHeader() {
			return String.format("VIRGIL.OWNER.%s", this.identityCardId);
		}

		String getSessionKeysKeyEntryName(String name) {
			return String.format("%s.%s.%s", this.getPrivateKeyEntryHeader(), SessPrefix, name);
		}

		boolean isLtKeyEntryName(String keyEntryName) {
			String prefix = String.format("%s.%s.", this.getPrivateKeyEntryHeader(), LtPrefix);
			return keyEntryName.contains(prefix);
		}

		boolean isOtKeyEntryName(String keyEntryName) {
			String prefix = String.format("%s.%s.", this.getPrivateKeyEntryHeader(), OtPrefix);
			return keyEntryName.contains(prefix);
		}

		boolean isPfsKeyEntryName(String keyEntryName) {
			return this.isOtKeyEntryName(keyEntryName) || this.isLtKeyEntryName(keyEntryName)
					|| this.isSessionKeysKeyEntryName(keyEntryName);
		}

		boolean isSessionKeysKeyEntryName(String keyEntryName) {
			String prefix = String.format("%s.%s.", this.getPrivateKeyEntryHeader(), SessPrefix);
			return keyEntryName.contains(prefix);
		}
	}

	public static class SessionKeys {
		private byte[] encryptionKey;
		private byte[] decryptionKey;

		/**
		 * Create new instance of {@link SessionKeys}.
		 * 
		 * @param value
		 *            the encryption and decryption keys date packed as single
		 *            array of bytes.
		 */
		public SessionKeys(byte[] value) {
			int pos = value.length / 2;
			this.encryptionKey = Arrays.copyOfRange(value, 0, pos);
			this.decryptionKey = Arrays.copyOfRange(value, pos, value.length);
		}

		/**
		 * Create new instance of {@link SessionKeys}.
		 * 
		 * @param encryptionKey
		 *            the encryption key data.
		 * @param decryptionKey
		 *            the decryption key data.
		 */
		public SessionKeys(byte[] encryptionKey, byte[] decryptionKey) {
			super();
			this.encryptionKey = encryptionKey;
			this.decryptionKey = decryptionKey;
		}

		/**
		 * @return the decryption key data.
		 */
		public byte[] getDecryptionKey() {
			return decryptionKey;
		}

		/**
		 * @return the encryption key data.
		 */
		public byte[] getEncryptionKey() {
			return encryptionKey;
		}

		/**
		 * @param decryptionKey
		 *            the decryption key data to set.
		 */
		public void setDecryptionKey(byte[] decryptionKey) {
			this.decryptionKey = decryptionKey;
		}

		/**
		 * @param encryptionKey
		 *            the encryption key data to set.
		 */
		public void setEncryptionKey(byte[] encryptionKey) {
			this.encryptionKey = encryptionKey;
		}

		/**
		 * Get enctyption and decryptions key as a signle array of bytes.
		 * 
		 * @return
		 */
		public byte[] toBytes() {
			int aLen = encryptionKey.length;
			int bLen = decryptionKey.length;
			byte[] c = new byte[aLen + bLen];
			System.arraycopy(encryptionKey, 0, c, 0, aLen);
			System.arraycopy(decryptionKey, 0, c, aLen, bLen);
			return c;
		}

	}

	public static final String SESSION_KEYS = "session";
	public static final String LT_KEYS = "lt";
	public static final String OT_KEYS = "ot";

	private Crypto crypto;

	private KeyStorage keyStorage;

	private KeyNamesHelper namesHelper;

	/**
	 * Create new instance of {@link KeyStorageManager}.
	 * 
	 * @param crypto
	 *            the crypto.
	 * @param keyStorage
	 *            the key storage.
	 * @param identityCardId
	 *            the identity's Virgil Card identifier.
	 */
	public KeyStorageManager(Crypto crypto, KeyStorage keyStorage, String identityCardId) {
		super();
		this.crypto = crypto;
		this.keyStorage = keyStorage;
		this.namesHelper = new KeyNamesHelper(identityCardId);
	}

	/**
	 * Reset the key storage.
	 */
	public void gentleReset() {
		List<KeyAttrs> keysAttrs = this.keyStorage.getAllKeysAttrs();

		for (KeyAttrs keyAttrs : keysAttrs) {
			if (this.namesHelper.isPfsKeyEntryName(keyAttrs.getName())) {
				this.removeKeyEntry(keyAttrs.getName());
			}
		}
	}

	/**
	 * Get attributes for all keys stored in key storage.
	 * 
	 * @return the map of keys grouped by type.
	 */
	public Map<String, List<KeyAttrs>> getAllKeysAttrs() {
		List<KeyAttrs> keysAttrs = this.keyStorage.getAllKeysAttrs();

		List<KeyAttrs> sessions = new ArrayList<>();
		List<KeyAttrs> lts = new ArrayList<>();
		List<KeyAttrs> ots = new ArrayList<>();
		for (KeyAttrs keyAttr : keysAttrs) {
			if (this.namesHelper.isSessionKeysKeyEntryName(keyAttr.getName())) {
				byte[] sessionId = this.namesHelper.extractSessionId(keyAttr.getName());

				String sessionIdStr = ConvertionUtils.toBase64String(sessionId);
				sessions.add(new KeyAttrs(sessionIdStr, keyAttr.getCreationDate()));
			} else if (this.namesHelper.isLtKeyEntryName(keyAttr.getName())) {
				String cardId = this.namesHelper.extractLTCardId(keyAttr.getName());
				lts.add(new KeyAttrs(cardId, keyAttr.getCreationDate()));
			} else if (this.namesHelper.isOtKeyEntryName(keyAttr.getName())) {
				String cardId = this.namesHelper.extractOTCardId(keyAttr.getName());
				ots.add(new KeyAttrs(cardId, keyAttr.getCreationDate()));
			}
		}

		Map<String, List<KeyAttrs>> map = new HashMap<>();
		map.put(SESSION_KEYS, sessions);
		map.put(LT_KEYS, lts);
		map.put(OT_KEYS, ots);

		return map;
	}

	public KeyEntry getKeyEntry(String keyEntryName) {
		return this.keyStorage.load(keyEntryName);
	}

	/**
	 * Get long term private key by name.
	 * 
	 * @param name
	 *            the key name.
	 * @return
	 * @throws CryptoException
	 */
	public PrivateKey getLtPrivateKey(String name) throws CryptoException {
		String keyEntryName = this.namesHelper.getLtPrivateKeyEntryName(name);
		return this.getPrivateKey(keyEntryName);
	}

	/**
	 * Get one-time private key by name.
	 * 
	 * @param name
	 *            the key name.
	 * @return
	 * @throws CryptoException
	 */
	public PrivateKey getOtPrivateKey(String name) throws CryptoException {
		String keyEntryName = this.namesHelper.getOtPrivateKeyEntryName(name);
		return this.getPrivateKey(keyEntryName);
	}

	/**
	 * Get private key by key entry name.
	 * 
	 * @param keyEntryName
	 *            the key entry name.
	 * @return
	 * @throws CryptoException
	 */
	public PrivateKey getPrivateKey(String keyEntryName) throws CryptoException {
		KeyEntry keyEntry = this.getKeyEntry(keyEntryName);
		PrivateKey privateKey = this.crypto.importPrivateKey(keyEntry.getValue());
		return privateKey;
	}

	/**
	 * Get session key by session identifier.
	 * 
	 * @param sessionId
	 *            the session identifier.
	 * @return
	 */
	public SessionKeys getSessionKeys(byte[] sessionId) {
		String sessionIdStr = ConvertionUtils.toBase64String(sessionId);
		String keyEntryName = this.namesHelper.getSessionKeysKeyEntryName(sessionIdStr);

		KeyEntry keyEntry = this.getKeyEntry(keyEntryName);

		return new SessionKeys(keyEntry.getValue());
	}

	/**
	 * Checks if relevant long term private key exist to the date {@code date}.
	 * 
	 * @param date
	 *            the date.
	 * @param longTermKeyTtl
	 *            the long term key time-to-live in seconds.
	 * @return {@code true} if relevant long term key exists.
	 */
	public boolean hasRelevantLtKey(Date date, int longTermKeyTtl) {
		List<KeyAttrs> keysAttrs = this.keyStorage.getAllKeysAttrs();
		if (keysAttrs.isEmpty()) {
			return false;
		}

		Calendar cal = Calendar.getInstance();
		cal.setTime(date);
		cal.add(Calendar.SECOND, -longTermKeyTtl);
		Date expiredDate = cal.getTime();

		for (KeyAttrs keyAttr : keysAttrs) {
			if (this.namesHelper.isLtKeyEntryName(keyAttr.getName()) && keyAttr.getCreationDate().after(expiredDate)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Checks if relevant long term private key exist to the current date.
	 * 
	 * @param longTermKeyTtl
	 *            the long term key time-to-live in seconds.
	 * @return {@code true} if relevant long term key exists.
	 */
	public boolean hasRelevantLtKey(int longTermKeyTtl) {
		return hasRelevantLtKey(new Date(), longTermKeyTtl);
	}

	void removeKeyEntries(List<String> keyEntryNames) {
		this.keyStorage.delete(keyEntryNames);
	}

	void removeKeyEntry(String keyEntryName) {
		this.keyStorage.delete(keyEntryName);
	}

	/**
	 * Remove long term private keys by names.
	 * 
	 * @param names
	 *            the list of private key names.
	 */
	public void removeLtPrivateKeys(List<String> names) {
		List<String> keyEntryNames = new ArrayList<>(names.size());
		for (String name : names) {
			keyEntryNames.add(this.namesHelper.getLtPrivateKeyEntryName(name));
		}
		this.removeKeyEntries(keyEntryNames);
	}

	/**
	 * Remove one-time private key by name.
	 * 
	 * @param name
	 *            the key name.
	 */
	public void removeOtPrivateKey(String name) {
		String keyEntryName = this.namesHelper.getOtPrivateKeyEntryName(name);
		this.removeKeyEntry(keyEntryName);
	}

	/**
	 * Remove one-time private keys by names.
	 * 
	 * @param names
	 *            the list of key names.
	 */
	public void removeOtPrivateKeys(List<String> names) {
		ArrayList<String> keyEntryNames = new ArrayList<>(names.size());
		for (String name : names) {
			keyEntryNames.add(this.namesHelper.getOtPrivateKeyEntryName(name));
		}
		this.removeKeyEntries(keyEntryNames);
	}

	/**
	 * Remove session keys by sessio identifier.
	 * 
	 * @param sessionId
	 *            the session identifier.
	 */
	public void removeSessionKeys(byte[] sessionId) {
		String sessionIdStr = ConvertionUtils.toBase64String(sessionId);
		String keyEntryName = this.namesHelper.getSessionKeysKeyEntryName(sessionIdStr);

		this.removeKeyEntry(keyEntryName);
	}

	/**
	 * Remove session keys by list of session identifiers.
	 * 
	 * @param sessionIds
	 *            the list of session identifiers.
	 */
	public void removeSessionKeys(List<byte[]> sessionIds) {
		List<String> keyEntryNames = new ArrayList<>(sessionIds.size());
		for (byte[] sessionId : sessionIds) {
			String name = ConvertionUtils.toBase64String(sessionId);
			keyEntryNames.add(this.namesHelper.getSessionKeysKeyEntryName(name));
		}
		this.removeKeyEntries(keyEntryNames);
	}

	/**
	 * Save key entries in key storage.
	 * 
	 * @param keyEntries
	 *            the key entries.
	 */
	public void saveKeyEntries(List<KeyEntry> keyEntries) {
		this.keyStorage.store(keyEntries);
	}

	/**
	 * Save key entry in key storage.
	 * 
	 * @param keyEntry
	 *            the key entry.
	 */
	public void saveKeyEntry(KeyEntry keyEntry) {
		this.keyStorage.store(keyEntry);
	}

	/**
	 * Save keys in key storage.
	 * 
	 * @param otKeys
	 *            one-time keys.
	 * @param ltKey
	 *            the long tem key.
	 */
	public void saveKeys(List<HelperKeyEntry> otKeys, HelperKeyEntry ltKey) {
		List<PrivateKey> privateKeys = new ArrayList<>(otKeys.size());
		List<String> names = new ArrayList<>(otKeys.size());
		for (HelperKeyEntry entry : otKeys) {
			privateKeys.add(entry.getPrivateKey());
			names.add(entry.getName());
		}

		this.saveOtPrivateKeys(privateKeys, names);

		if (ltKey != null) {
			this.saveLtPrivateKey(ltKey.getPrivateKey(), ltKey.getName());
		}
	}

	private void saveLtPrivateKey(PrivateKey key, String name) {
		String keyEntryName = this.namesHelper.getLtPrivateKeyEntryName(name);
		this.savePrivateKey(key, keyEntryName);
	}

	private void saveOtPrivateKeys(List<PrivateKey> keys, List<String> names) {
		ArrayList<String> keyEntryNames = new ArrayList<>(names.size());
		for (String name : names) {
			keyEntryNames.add(this.namesHelper.getOtPrivateKeyEntryName(name));
		}
		this.savePrivateKeys(keys, keyEntryNames);
	}

	void savePrivateKey(PrivateKey key, String keyEntryName) {
		byte[] privateKeyData = this.crypto.exportPrivateKey(key);

		KeyEntry keyEntry = new VirgilKeyEntry(keyEntryName, privateKeyData);

		this.saveKeyEntry(keyEntry);
	}

	public void savePrivateKeys(List<PrivateKey> keys, List<String> keyEntryNames) {
		List<KeyEntry> keyEntries = new ArrayList<>(Math.min(keys.size(), keyEntryNames.size()));
		Iterator<String> namesIt = keyEntryNames.iterator();
		for (Iterator<PrivateKey> keysIt = keys.iterator(); keysIt.hasNext() && namesIt.hasNext();) {
			String name = namesIt.next();
			PrivateKey privateKey = keysIt.next();
			byte[] privateKeyData = this.crypto.exportPrivateKey(privateKey);

			KeyEntry keyEntry = new VirgilKeyEntry(name, privateKeyData);
			keyEntries.add(keyEntry);
		}
		this.saveKeyEntries(keyEntries);
	}

	public void saveSessionKeys(SessionKeys sessionKeys, byte[] sessionId) {
		String sessionIdStr = ConvertionUtils.toBase64String(sessionId);
		String keyEntryName = this.namesHelper.getSessionKeysKeyEntryName(sessionIdStr);

		KeyEntry keyEntry = new VirgilKeyEntry(keyEntryName, sessionKeys.toBytes());

		this.saveKeyEntry(keyEntry);
	}
}
