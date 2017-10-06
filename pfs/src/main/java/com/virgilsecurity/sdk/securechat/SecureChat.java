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

import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import com.virgilsecurity.sdk.client.exceptions.CardValidationException;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.pfs.VirgilPFSClient;
import com.virgilsecurity.sdk.pfs.model.RecipientCardsSet;
import com.virgilsecurity.sdk.securechat.exceptions.MigrationException;
import com.virgilsecurity.sdk.securechat.exceptions.SecureChatException;
import com.virgilsecurity.sdk.securechat.exceptions.SessionManagerException;
import com.virgilsecurity.sdk.securechat.migration.MigrationManager;
import com.virgilsecurity.sdk.securechat.model.CardEntry;
import com.virgilsecurity.sdk.securechat.model.InitiationMessage;
import com.virgilsecurity.sdk.securechat.model.Message;
import com.virgilsecurity.sdk.securechat.model.MessageType;
import com.virgilsecurity.sdk.securechat.session.SecureSession;
import com.virgilsecurity.sdk.securechat.session.SessionInitializer;
import com.virgilsecurity.sdk.securechat.session.SessionManager;
import com.virgilsecurity.sdk.securechat.utils.SessionStateResolver;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChat {

	public enum Version {
		V1_0("1.0"), V1_1("1.1");

		// Current version
		public static Version currentVersion = Version.V1_1;

		public static Version fromString(String text) {
			for (Version v : Version.values()) {
				if (v.code.equalsIgnoreCase(text)) {
					return v;
				}
			}
			return V1_0;
		}

		@SuppressWarnings("incomplete-switch")
		public static Version[] getSortedVersions(Version version) {
			switch (version) {
			case V1_0:
				return new Version[] { V1_1 };
			}
			return new Version[0];
		}

		private String code;

		private Version(String code) {
			this.code = code;
		}
	}

	private static final String CONFIGURATION_STORAGE_KEY = "CONFIGURATION_STORAGE";

	private static final Logger log = Logger.getLogger(SecureChat.class.getName());

	public static MessageType getMessageType(String message) {
		if (SessionStateResolver.isInitiationMessage(message)) {
			return MessageType.INITIAL;
		} else if (SessionStateResolver.isRegularMessage(message)) {
			return MessageType.REGULAR;
		}

		return MessageType.UNKNOWN;
	}

	// User's identity card identifier
	private String identityCardId;
	private VirgilPFSClient client;
	private EphemeralCardsReplenisher ephemeralCardsReplenisher;
	private SessionManager sessionManager;
	private KeysRotator rotator;

	private UserDataStorage insensitiveDataStorage;

	private MigrationManager migrationManager;

	/**
	 * Create new instance of {@link SecureChat}.
	 * 
	 * @param config
	 *            the secure chat context.
	 */
	public SecureChat(SecureChatContext config) {
		this.identityCardId = config.getIdentityCard().getId();
		this.client = new VirgilPFSClient(config.getContext());
		this.insensitiveDataStorage = config.getUserDataStorage();

		KeyStorageManager keyStorageManager = new KeyStorageManager(config.getCrypto(), config.getKeyStorage(),
				identityCardId);
		this.ephemeralCardsReplenisher = new EphemeralCardsReplenisher(config.getCrypto(),
				config.getIdentityPrivateKey(), identityCardId, this.client, keyStorageManager);

		SessionStorageManager sessionStorageManager = new SessionStorageManager(identityCardId,
				config.getUserDataStorage());

		ExhaustInfoManager exhaustInfoManager = new ExhaustInfoManager(identityCardId, config.getUserDataStorage());

		SessionInitializer sessionInitializer = new SessionInitializer(config.getCrypto(),
				config.getIdentityPrivateKey(), config.getIdentityCard());
		this.sessionManager = new SessionManager(config.getIdentityCard(), config.getIdentityPrivateKey(),
				config.getCrypto(), config.getSessionTtl(), keyStorageManager, sessionStorageManager,
				sessionInitializer);

		this.rotator = new KeysRotator(config.getIdentityCard(), config.getExhaustedOneTimeKeysTtl(),
				config.getExpiredSessionTtl(), config.getLongTermKeysTtl(), config.getExpiredLongTermKeysTtl(),
				this.ephemeralCardsReplenisher, sessionStorageManager, keyStorageManager, exhaustInfoManager,
				this.client);

		this.migrationManager = new MigrationManager(config.getCrypto(), config.getIdentityPrivateKey(),
				config.getIdentityCard(), config.getKeyStorage(), keyStorageManager, config.getUserDataStorage(),
				sessionInitializer, sessionManager);

	}

	/**
	 * Returns latest active session with specified participant, if present.
	 * 
	 * @param cardId
	 *            The participant's Virgil Card identifier
	 * @return {@link SecureSession} if session is found, {@code null} if
	 *         session is not exists.
	 */
	public SecureSession activeSession(String cardId) {
		log.fine(String.format("SecureChat: %s. Searching for active session for: %s", this.identityCardId, cardId));

		return this.sessionManager.activeSession(cardId);
	}

	/**
	 * Reset chat.
	 */
	public void gentleReset() {
		this.sessionManager.gentleReset();
	}

	public Version getPreviousVersion() {
		String versionStr = this.insensitiveDataStorage.getData(CONFIGURATION_STORAGE_KEY, this.getVersionKey());
		Version version = Version.fromString(versionStr);

		return version;
	}

	private String getVersionKey() {
		return String.format("VIRGIL.OWNER=%s.VERSION", this.identityCardId);
	}

	/**
	 * Initializes SecureChat and migrate existing data.
	 * 
	 * @throws MigrationException
	 */
	public void initialize() throws MigrationException {
		initialize(true);
	}

	/**
	 * Initializes SecureChat
	 * 
	 * @param migrateAutomatically
	 *            If {@code true} existing data will be migrated automatically.
	 * @throws MigrationException
	 */
	public void initialize(boolean migrateAutomatically) throws MigrationException {
		if (migrateAutomatically) {
			this.migrate();
		}
	}

	/**
	 * Loads existing session using with given participant using received
	 * message.
	 * 
	 * @param card
	 *            The participant's identity Virgil Card. WARNING: Identity Card
	 *            should be validated before getting here!
	 * @param message
	 *            Received message from this participant.
	 * @param additionalData
	 *            Data for additional authorization (e.g. concatenated
	 *            usernames). AdditionalData should be equal on both participant
	 *            sides. AdditionalData should be constracted on both sides
	 *            independently and should NOT be transmitted for security
	 *            reasons.
	 * @return Initialized {@link SecureSession}.
	 * @throws SecureChatException
	 */
	public SecureSession loadUpSession(CardModel card, String message, byte[] additionalData)
			throws SecureChatException {
		log.fine(String.format("SecureChat: %s. Loading session with: %s", this.identityCardId, card.getId()));

		if (SessionStateResolver.isInitiationMessage(message)) {
			InitiationMessage initiationMessage = SecureSession.extractInitiationMessage(message);
			// Add new one time card if we have received strong session
			if (!StringUtils.isBlank(initiationMessage.getResponderOtcId())) {
				try {
					this.ephemeralCardsReplenisher.addCards(false, 1);
				} catch (Exception e) {
					log.warning(String.format(
							"SecureChat: %s. WARNING: Error occured while adding new otc in loadUpSession",
							this.identityCardId));
					return null;
				}
			}

			CardEntry cardEntry = new CardEntry(card.getId(), card.getSnapshotModel().getPublicKeyData());

			return this.sessionManager.initializeResponderSession(cardEntry, initiationMessage, additionalData);
		} else if (SessionStateResolver.isRegularMessage(message)) {
			Message regularMessage = SecureSession.extractMessage(message);
			byte[] sessionId = regularMessage.getSessionId();

			return this.sessionManager.loadSession(card.getId(), sessionId);
		} else {
			throw new SecureChatException(Constants.Errors.SecureChat.UNKNOWN_MESSAGE_STRUCTURE,
					"Unknown message structure.");
		}
	}

	public void migrate() throws MigrationException {
		Version previousVersion = this.getPreviousVersion();
		this.migrate(previousVersion);

		// Update version
		this.insensitiveDataStorage.addData(CONFIGURATION_STORAGE_KEY, this.getVersionKey(),
				Version.currentVersion.code);
	}

	private void migrate(Version previousVersion) throws MigrationException {
		Version[] migrationVersions = Version.getSortedVersions(previousVersion);

		log.fine(String.format("Versions to migrate: %s", String.valueOf(migrationVersions)));

		for (Version migrationVersion : migrationVersions) {
			switch (migrationVersion) {
			case V1_0:
				break;
			case V1_1:
				this.migrationManager.migrateToV1_1();
			}
		}
	}

	/**
	 * Removes session with given participant and session identifier.
	 * 
	 * @param cardId
	 *            The participant's identity Virgil Card identifier
	 * @param sessionId
	 *            The session identifier.
	 */
	public void removeSession(String cardId, byte[] sessionId) {
		this.sessionManager.removeSession(cardId, sessionId);
	}

	/**
	 * Removes all sessions with given participant.
	 * 
	 * @param cardId
	 *            The participant's identity Virgil Card identifier.
	 */
	public void removeSessions(String cardId) {
		this.sessionManager.removeSessions(cardId);
	}

	/**
	 * Periodic Keys processing.
	 * 
	 * This method:
	 * <ol>
	 * <li>Removes expired long-terms keys and adds new if needed
	 * <li>Removes orphances one-time keys
	 * <li>Removes expired sessions
	 * <li>Removes orphaned session keys
	 * <li>Adds new one-time keys if needed
	 * </ol>
	 * 
	 * WARNING: This method is called during initialization. It's up to you to
	 * call this method after that periodically, since iOS app can stay in
	 * memory for any period of time without restarting. Recommended period:
	 * 24h.
	 * 
	 * @param desiredNumberOfCards
	 *            The desired number of one-time cards.
	 */
	public void rotateKeys(int desiredNumberOfCards) {
		this.rotator.rotateKeys(desiredNumberOfCards);
	}

	/**
	 * Starts new session with given recipient.
	 * 
	 * @param recipientCard
	 *            The recipient's identity Virgil Card. WARNING: Identity Card
	 *            should be validated before getting here!
	 * @param additionalData
	 *            Data for additional authorization (e.g. concatenated
	 *            usernames). AdditionalData should be equal on both participant
	 *            sides. AdditionalData should be constracted on both sides
	 *            independently and should NOT be transmitted for security
	 *            reasons.
	 * @return The initialized {@link SecureSession}.
	 * @throws SecureChatException
	 * @throws CardValidationException
	 */
	public SecureSession startNewSession(CardModel recipientCard, byte[] additionalData)
			throws SecureChatException, CardValidationException {
		log.fine(String.format("SecureChat: %s. Starting new session with: %s", this.identityCardId,
				recipientCard.getId()));

		this.sessionManager.checkExistingSessionOnStart(recipientCard.getId());

		// Get recipient's credentials
		List<RecipientCardsSet> cardsSets = null;
		try {
			cardsSets = this.client.getRecipientCardsSet(Arrays.asList(recipientCard.getId()));
		} catch (Exception e) {
			throw new SecureChatException(Constants.Errors.SecureChat.OBTAINING_RECIPIENT_CARDS_SET,
					"Error obtaining recipient cards set.", e);
		}
		if (cardsSets.isEmpty()) {
			throw new SecureChatException(Constants.Errors.SecureChat.RECIPIENT_SET_EMPTY,
					"Error obtaining recipient cards set. Empty set.");
		}

		// FIXME Multiple sessions?
		RecipientCardsSet cardsSet = cardsSets.get(0);

		SecureSession session = this.startNewSession(recipientCard, cardsSet, additionalData);
		return session;
	}

	private SecureSession startNewSession(CardModel recipientCard, RecipientCardsSet cardsSet, byte[] additionalData)
			throws SessionManagerException {
		log.fine(String.format("SecureChat: %s. Starting new session with cards set with: %s", this.identityCardId,
				recipientCard.getId()));

		return this.sessionManager.initializeInitiatorSession(recipientCard, cardsSet, additionalData);
	}

	/**
	 * Wipes cache used for loadUp and activeSession functions.
	 */
	public void wipeCache() {
		this.sessionManager.wipeCache();
	}

}
