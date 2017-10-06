package com.virgilsecurity.sdk.securechat.migration;

import java.util.logging.Logger;

import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.securechat.KeyStorageManager;
import com.virgilsecurity.sdk.securechat.UserDataStorage;
import com.virgilsecurity.sdk.securechat.exceptions.MigrationException;
import com.virgilsecurity.sdk.securechat.keystorage.KeyStorage;
import com.virgilsecurity.sdk.securechat.migration.v1_1.MigrationV1_1;
import com.virgilsecurity.sdk.securechat.session.SessionInitializer;
import com.virgilsecurity.sdk.securechat.session.SessionManager;

public class MigrationManager {

	private static final Logger log = Logger.getLogger(MigrationManager.class.getName());

	private Crypto crypto;
	private PrivateKey identityPrivateKey;
	private CardModel identityCard;
	private KeyStorage keyStorage;
	private KeyStorageManager keyStorageManager;
	private UserDataStorage storage;
	private SessionInitializer sessionInitializer;
	private SessionManager sessionManager;

	/**
	 * Create new instance of {@link MigrationManager}
	 * 
	 * @param crypto
	 * @param identityPrivateKey
	 * @param identityCard
	 * @param keyStorage
	 * @param keyStorageManager
	 * @param storage
	 * @param sessionInitializer
	 * @param sessionManager
	 */
	public MigrationManager(Crypto crypto, PrivateKey identityPrivateKey, CardModel identityCard, KeyStorage keyStorage,
			KeyStorageManager keyStorageManager, UserDataStorage storage, SessionInitializer sessionInitializer,
			SessionManager sessionManager) {
		super();
		this.crypto = crypto;
		this.identityPrivateKey = identityPrivateKey;
		this.identityCard = identityCard;
		this.keyStorage = keyStorage;
		this.keyStorageManager = keyStorageManager;
		this.storage = storage;
		this.sessionInitializer = sessionInitializer;
		this.sessionManager = sessionManager;
	}

	public void migrateToV1_1() throws MigrationException {
		log.fine("Migrating to 1.1");

		MigrationV1_1 migration = new MigrationV1_1(this.crypto, this.identityPrivateKey, this.identityCard,
				this.keyStorage, this.keyStorageManager, this.storage, this.sessionInitializer, this.sessionManager);

		migration.migrateKeyStorage();
		migration.migrate();
	}
}
