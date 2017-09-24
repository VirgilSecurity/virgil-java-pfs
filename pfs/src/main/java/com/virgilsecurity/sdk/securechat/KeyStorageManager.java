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

public class KeyStorageManager {

	public static final String SESSION_KEYS = "session";
	public static final String LT_KEYS = "lt";
	public static final String OT_KEYS = "ot";

	private Crypto crypto;
	private KeyStorage keyStorage;
	private KeyNamesHelper namesHelper;

	/**
	 * @param crypto
	 * @param keyStorage
	 * @param identityCardId
	 */
	public KeyStorageManager(Crypto crypto, KeyStorage keyStorage, String identityCardId) {
		super();
		this.crypto = crypto;
		this.keyStorage = keyStorage;
		this.namesHelper = new KeyNamesHelper(identityCardId);
	}

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

	public boolean hasRelevantLtKey(int longTermKeyTtl) {
		return hasRelevantLtKey(new Date(), longTermKeyTtl);
	}

	// FIXME LTC TTL
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

	public void gentleReset() {
		List<KeyAttrs> keysAttrs = this.keyStorage.getAllKeysAttrs();

		for (KeyAttrs keyAttrs : keysAttrs) {
			if (this.namesHelper.isPfsKeyEntryName(keyAttrs.getName())) {
				this.removeKeyEntry(keyAttrs.getName());
			}
		}
	}

	public SessionKeys getSessionKeys(byte[] sessionId) {
		String sessionIdStr = ConvertionUtils.toBase64String(sessionId);
		String keyEntryName = this.namesHelper.getSessionKeysKeyEntryName(sessionIdStr);

		KeyEntry keyEntry = this.getKeyEntry(keyEntryName);

		return new SessionKeys(keyEntry.getValue());
	}

	/**
	 * 
	 * @return
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

	public void saveSessionKeys(SessionKeys sessionKeys, byte[] sessionId) {
		String sessionIdStr = ConvertionUtils.toBase64String(sessionId);
		String keyEntryName = this.namesHelper.getSessionKeysKeyEntryName(sessionIdStr);

		KeyEntry keyEntry = new VirgilKeyEntry(keyEntryName, sessionKeys.toBytes());

		this.saveKeyEntry(keyEntry);
	}

	public void removeSessionKeys(byte[] sessionId) {
		String sessionIdStr = ConvertionUtils.toBase64String(sessionId);
		String keyEntryName = this.namesHelper.getSessionKeysKeyEntryName(sessionIdStr);

		this.removeKeyEntry(keyEntryName);
	}

	public void removeSessionKeys(List<byte[]> sessionIds) {
		List<String> keyEntryNames = new ArrayList<>(sessionIds.size());
		for (byte[] sessionId : sessionIds) {
			String name = ConvertionUtils.toBase64String(sessionId);
			keyEntryNames.add(this.namesHelper.getSessionKeysKeyEntryName(name));
		}
		this.removeKeyEntries(keyEntryNames);
	}

	// Lt keys
	public PrivateKey getLtPrivateKey(String name) throws CryptoException {
		String keyEntryName = this.namesHelper.getLtPrivateKeyEntryName(name);
		return this.getPrivateKey(keyEntryName);
	}

	private void saveLtPrivateKey(PrivateKey key, String name) {
		String keyEntryName = this.namesHelper.getLtPrivateKeyEntryName(name);
		this.savePrivateKey(key, keyEntryName);
	}

	public void removeLtPrivateKeys(List<String> names) {
		List<String> keyEntryNames = new ArrayList<>(names.size());
		for (String name : names) {
			keyEntryNames.add(this.namesHelper.getLtPrivateKeyEntryName(name));
		}
		this.removeKeyEntries(keyEntryNames);
	}

	// Ot keys
	public PrivateKey getOtPrivateKey(String name) throws CryptoException {
		String keyEntryName = this.namesHelper.getOtPrivateKeyEntryName(name);
		return this.getPrivateKey(keyEntryName);
	}

	private void saveOtPrivateKeys(List<PrivateKey> keys, List<String> names) {
		ArrayList<String> keyEntryNames = new ArrayList<>(names.size());
		for (String name : names) {
			keyEntryNames.add(this.namesHelper.getOtPrivateKeyEntryName(name));
		}
		this.savePrivateKeys(keys, keyEntryNames);
	}

	public void removeOtPrivateKey(String name) {
		String keyEntryName = this.namesHelper.getOtPrivateKeyEntryName(name);
		this.removeKeyEntry(keyEntryName);
	}

	public void removeOtPrivateKeys(List<String> names) {
		ArrayList<String> keyEntryNames = new ArrayList<>(names.size());
		for (String name : names) {
			keyEntryNames.add(this.namesHelper.getOtPrivateKeyEntryName(name));
		}
		this.removeKeyEntries(keyEntryNames);
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

	public void saveKeyEntry(KeyEntry keyEntry) {
		this.keyStorage.store(keyEntry);
	}

	public void saveKeyEntries(List<KeyEntry> keyEntries) {
		this.keyStorage.store(keyEntries);
	}

	public PrivateKey getPrivateKey(String keyEntryName) throws CryptoException {
		KeyEntry keyEntry = this.getKeyEntry(keyEntryName);
		PrivateKey privateKey = this.crypto.importPrivateKey(keyEntry.getValue());
		return privateKey;
	}

	KeyEntry getKeyEntry(String keyEntryName) {
		return this.keyStorage.load(keyEntryName);
	}

	void removeKeyEntry(String keyEntryName) {
		this.keyStorage.delete(keyEntryName);
	}

	void removeKeyEntries(List<String> keyEntryNames) {
		this.keyStorage.delete(keyEntryNames);
	}

	public static class KeyNamesHelper {
		private static final String OtPrefix = "OT_KEY";
		private static final String LtPrefix = "LT_KEY";
		private static final String SessPrefix = "SESS_KEYS";

		private String identityCardId;

		public KeyNamesHelper(String identityCardId) {
			this.identityCardId = identityCardId;
		}

		String extractOTCardId(String keyEntryName) {
			String prefix = String.format("%s.%s.", this.getPrivateKeyEntryHeader(), OtPrefix);
			return keyEntryName.replace(prefix, "");
		}

		String extractLTCardId(String keyEntryName) {
			String prefix = String.format("%s.%s.", this.getPrivateKeyEntryHeader(), LtPrefix);
			return keyEntryName.replace(prefix, "");
		}

		byte[] extractSessionId(String keyEntryName) {
			String prefix = String.format("%s.%s.", this.getPrivateKeyEntryHeader(), SessPrefix);
			String id = keyEntryName.replace(prefix, "");
			return ConvertionUtils.base64ToBytes(id);
		}

		boolean isPfsKeyEntryName(String keyEntryName) {
			return this.isOtKeyEntryName(keyEntryName) || this.isLtKeyEntryName(keyEntryName)
					|| this.isSessionKeysKeyEntryName(keyEntryName);
		}

		String getSessionKeysKeyEntryName(String name) {
			return String.format("%s.%s.%s", this.getPrivateKeyEntryHeader(), SessPrefix, name);
		}

		boolean isSessionKeysKeyEntryName(String keyEntryName) {
			String prefix = String.format("%s.%s.", this.getPrivateKeyEntryHeader(), SessPrefix);
			return keyEntryName.contains(prefix);
		}

		String getLtPrivateKeyEntryName(String name) {
			return String.format("%s.%s.%s", this.getPrivateKeyEntryHeader(), LtPrefix, name);
		}

		boolean isLtKeyEntryName(String keyEntryName) {
			String prefix = String.format("%s.%s.", this.getPrivateKeyEntryHeader(), LtPrefix);
			return keyEntryName.contains(prefix);
		}

		String getOtPrivateKeyEntryName(String name) {
			return String.format("%s.%s.%s", this.getPrivateKeyEntryHeader(), OtPrefix, name);
		}

		boolean isOtKeyEntryName(String keyEntryName) {
			String prefix = String.format("%s.%s.", this.getPrivateKeyEntryHeader(), OtPrefix);
			return keyEntryName.contains(prefix);
		}

		private String getPrivateKeyEntryHeader() {
			return String.format("VIRGIL.OWNER=%s", this.identityCardId);
		}
	}

	public static class HelperKeyEntry {
		private PrivateKey privateKey;
		String name;

		/**
		 * 
		 */
		public HelperKeyEntry() {
		}

		/**
		 * @param privateKey
		 * @param name
		 */
		public HelperKeyEntry(PrivateKey privateKey, String name) {
			this.privateKey = privateKey;
			this.name = name;
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
		 * @return the name
		 */
		public String getName() {
			return name;
		}

		/**
		 * @param name
		 *            the name to set
		 */
		public void setName(String name) {
			this.name = name;
		}

	}

	public static class SessionKeys {
		private byte[] encryptionKey;
		private byte[] decryptionKey;

		public SessionKeys(byte[] value) {
			int pos = value.length / 2;
			this.encryptionKey = Arrays.copyOfRange(value, 0, pos);
			this.decryptionKey = Arrays.copyOfRange(value, pos, value.length);
		}

		/**
		 * @param encryptionKey
		 * @param decryptionKey
		 */
		public SessionKeys(byte[] encryptionKey, byte[] decryptionKey) {
			super();
			this.encryptionKey = encryptionKey;
			this.decryptionKey = decryptionKey;
		}

		public byte[] toBytes() {
			int aLen = encryptionKey.length;
			int bLen = decryptionKey.length;
			byte[] c = new byte[aLen + bLen];
			System.arraycopy(encryptionKey, 0, c, 0, aLen);
			System.arraycopy(decryptionKey, 0, c, aLen, bLen);
			return c;
		}

		/**
		 * @return the encryptionKey
		 */
		public byte[] getEncryptionKey() {
			return encryptionKey;
		}

		/**
		 * @param encryptionKey
		 *            the encryptionKey to set
		 */
		public void setEncryptionKey(byte[] encryptionKey) {
			this.encryptionKey = encryptionKey;
		}

		/**
		 * @return the decryptionKey
		 */
		public byte[] getDecryptionKey() {
			return decryptionKey;
		}

		/**
		 * @param decryptionKey
		 *            the decryptionKey to set
		 */
		public void setDecryptionKey(byte[] decryptionKey) {
			this.decryptionKey = decryptionKey;
		}

	}
}
