package com.virgilsecurity.sdk.securechat.keystorage;

import java.util.List;

import com.virgilsecurity.sdk.storage.KeyEntry;

public interface KeyStorage extends com.virgilsecurity.sdk.storage.KeyStorage {

	/**
	 * Stores the private keys (that has already been protected) to the given
	 * alias.
	 * 
	 * @param keyEntries
	 *            Key entries.
	 */
	void store(List<KeyEntry> keyEntries);

	/**
	 * Deletes the private keys from key store by given Ids.
	 * 
	 * @param keyNames
	 *            Key names.
	 */
	void delete(List<String> keyName);

	/**
	 * Returns all keys attributes
	 * 
	 * @return all keys attributes
	 */
	List<KeyAttrs> getAllKeysAttrs();

}
