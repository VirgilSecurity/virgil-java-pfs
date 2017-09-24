package com.virgilsecurity.sdk.securechat.session;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.pfs.EphemeralCardValidator;
import com.virgilsecurity.sdk.pfs.model.RecipientCardsSet;
import com.virgilsecurity.sdk.securechat.Constants;
import com.virgilsecurity.sdk.securechat.KeyStorageManager;
import com.virgilsecurity.sdk.securechat.KeyStorageManager.SessionKeys;
import com.virgilsecurity.sdk.securechat.KeysRotator;
import com.virgilsecurity.sdk.securechat.SessionStorageManager;
import com.virgilsecurity.sdk.securechat.exceptions.SessionManagerException;
import com.virgilsecurity.sdk.securechat.model.CardEntry;
import com.virgilsecurity.sdk.securechat.model.InitiationMessage;
import com.virgilsecurity.sdk.securechat.model.SessionState;
import com.virgilsecurity.sdk.securechat.utils.ArrayUtils;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

public class SessionManager {
	private static final Logger log = Logger.getLogger(KeysRotator.class.getName());

	private CardModel identityCard;
	private PrivateKey identityPrivateKey;
	private Crypto crypto;
	private int sessionTtl;
	private KeyStorageManager keyStorageManager;
	private SessionStorageManager sessionStorageManager;
	private SessionInitializer sessionInitializer;

	private Map<byte[], SecureSession> loadUpCache;
	private Map<String, SecureSession> activeSessionCache;

	public SessionManager() {
		this.loadUpCache = Collections
				.synchronizedMap(new TreeMap<byte[], SecureSession>(new ArrayUtils.ArrayComparator()));
		this.activeSessionCache = new ConcurrentHashMap<>();
	}

	public SessionManager(CardModel card, PrivateKey privateKey, Crypto crypto, int sessionTtl,
			KeyStorageManager keyStorageManager, SessionStorageManager sessionStorageManager,
			SessionInitializer sessionInitializer) {
		this();
		this.identityCard = card;
		this.identityPrivateKey = privateKey;
		this.crypto = crypto;
		this.keyStorageManager = keyStorageManager;
		this.sessionStorageManager = sessionStorageManager;
		this.sessionInitializer = sessionInitializer;
		this.sessionTtl = sessionTtl;
	}

	public SecureSession activeSession(String cardId) {
		Date now = new Date();

		SecureSession session = this.activeSessionCache.get(cardId);
		if (session != null && !session.isExpired(now)) {
			return session;
		}

		SessionState sessionState = this.sessionStorageManager.getNewestSessionState(cardId);
		if (sessionState == null || sessionState.isExpired(now)) {
			return null;
		}

		session = this.loadUpCache.get(sessionState.getSessionId());
		if (session != null) {
			this.activeSessionCache.put(cardId, session);
			return session;
		} else {
			try {
				session = this.recoverSession(this.identityCard, sessionState);

				// Put session in caches
				this.activeSessionCache.put(cardId, session);
				this.loadUpCache.put(session.getIdentifier(), session);

				return session;
			} catch (Exception e) {
				log.severe(String.format("Error while recovering session: %s", e.getMessage()));
				return null;
			}
		}
	}

	public void wipeCache() {
		this.loadUpCache = new HashMap<>();
		this.activeSessionCache = new HashMap<>();
	}

	public void saveSession(SecureSession session, Date creationDate, String participantCardId) {
		byte[] sessionId = session.getIdentifier();
		byte[] encryptionKey = session.getEncryptionKey();
		byte[] decryptionKey = session.getDecryptionKey();

		SessionKeys sessionKeys = new KeyStorageManager.SessionKeys(encryptionKey, decryptionKey);

		this.keyStorageManager.saveSessionKeys(sessionKeys, sessionId);

		SessionState sessionState = new SessionState(session.getIdentifier(), creationDate, session.getExpirationDate(),
				session.getAdditionalData());

		this.sessionStorageManager.addSessionState(sessionState, participantCardId);
	}

	public void checkExistingSessionOnStart(String recipientCardId) {
		if (this.activeSessionCache.containsKey(recipientCardId)) {
			log.severe(String.format(
					"Found active cached session for %s. Try to loadUpSession:, if that fails try to remove session.",
					recipientCardId));
			return;
		}

		SessionState sessionState = this.sessionStorageManager.getNewestSessionState(recipientCardId);

		if (sessionState != null && !sessionState.isExpired()) {
			log.severe(String.format(
					"Found active session for %s. Try to loadUpSession:, if that fails try to remove session.",
					recipientCardId));
		}
	}

	public SecureSession loadSession(String recipientCardId, byte[] sessionId) throws SessionManagerException {
		// Look for cached value
		SecureSession session = this.loadUpCache.get(sessionId);
		if (session != null) {
			return session;
		}

		SessionState sessionState = this.sessionStorageManager.getSessionState(recipientCardId, sessionId);
		if (sessionState == null || !Arrays.equals(sessionState.getSessionId(), sessionId)) {
			throw new SessionManagerException(Constants.Errors.SessionManager.SESSION_NOT_FOUND, "Session not found.");
		}

		session = this.recoverSession(this.identityCard, sessionState);

		this.loadUpCache.put(sessionId, session);

		return session;
	}

	public SecureSession initializeResponderSession(CardEntry initiatorCardEntry, InitiationMessage initiationMessage,
			byte[] additionalData) throws SessionManagerException {
		PublicKey initiatorPublicKey;
		try {
			initiatorPublicKey = this.crypto.importPublicKey(initiatorCardEntry.getPublicKeyData());
		} catch (Exception e) {
			throw new SessionManagerException(
					Constants.Errors.SessionManager.IMPORTING_INITIATOR_PUBLIC_KEY_FROM_IDENTITY_CARD,
					"Error importing initiator public key from identity card.", e);
		}

		try {
			boolean valid = this.crypto.verify(initiationMessage.getEphPublicKey(),
					initiationMessage.getEphPublicKeySignature(), initiatorPublicKey);
			if (!valid) {
				throw new VirgilException();
			}
		} catch (Exception e) {
			throw new SessionManagerException(Constants.Errors.SessionManager.VALIDATING_INITIATOR_SIGNATURE,
					"Error validating initiator signature.", e);
		}

		if (!initiationMessage.getInitiatorIcId().equals(initiatorCardEntry.getIdentifier())) {
			throw new SessionManagerException(Constants.Errors.SessionManager.INITIATOR_IDENTITY_CARD_ID_DOESNT_MATCH,
					"Initiator identity card id for this session and InitiationMessage doesn't match.");
		}

		PrivateKey ltPrivateKey = null;
		try {
			ltPrivateKey = this.keyStorageManager.getLtPrivateKey(initiationMessage.getResponderLtcId());
		} catch (CryptoException e) {
			throw new SessionManagerException(Constants.Errors.SessionManager.GET_RESPONDER_LT,
					"Can't get responcer LT card", e);
		}

		PrivateKey otPrivateKey = null;
		if (!StringUtils.isBlank(initiationMessage.getResponderOtcId())) {
			String recponderOtcId = initiationMessage.getResponderOtcId();
			try {
				otPrivateKey = this.keyStorageManager.getOtPrivateKey(recponderOtcId);
			} catch (CryptoException e) {
				throw new SessionManagerException(Constants.Errors.SessionManager.GET_RESPONDER_OT,
						"Can't get responcer OT card", e);
			}
			this.keyStorageManager.removeOtPrivateKey(recponderOtcId);
		}

		Calendar cal = Calendar.getInstance();
		Date creationDate = cal.getTime();
		cal.add(Calendar.SECOND, this.sessionTtl);
		Date expirationDate = cal.getTime();

		SecureSession secureSession = this.sessionInitializer.initializeResponderSession(initiatorCardEntry,
				this.identityPrivateKey, ltPrivateKey, otPrivateKey, initiationMessage.getEphPublicKey(),
				additionalData, expirationDate);

		this.saveSession(secureSession, creationDate, initiatorCardEntry.getIdentifier());

		this.addNewSessionToCache(secureSession, initiatorCardEntry.getIdentifier());

		return secureSession;
	}

	public SecureSession initializeInitiatorSession(CardModel recipientCard, RecipientCardsSet cardsSet,
			byte[] additionalData) throws SessionManagerException {
		if (cardsSet.getOneTimeCard() == null) {
			log.warning("WARNING: Creating weak session with " + recipientCard.getId());
		}

		String identityCardId = recipientCard.getId();
		byte[] identityPublicKeyData = recipientCard.getSnapshotModel().getPublicKeyData();
		byte[] longTermPublicKeyData = cardsSet.getLongTermCard().getSnapshotModel().getPublicKeyData();

		byte[] oneTimePublicKeyData = null;
		if (cardsSet.getOneTimeCard() != null) {
			oneTimePublicKeyData = cardsSet.getOneTimeCard().getSnapshotModel().getPublicKeyData();
		}

		KeyPair ephKeyPair = this.crypto.generateKeys();
		PrivateKey ephPrivateKey = ephKeyPair.getPrivateKey();

		EphemeralCardValidator validator = new EphemeralCardValidator(this.crypto);

		try {
			validator.addVerifier(identityCardId, identityPublicKeyData);
		} catch (Exception e) {
			throw new SessionManagerException(Constants.Errors.SessionManager.ADD_VERIFIER,
					"Error while adding verifier.", e);
		}

		if (!validator.validate(cardsSet.getLongTermCard())) {
			throw new SessionManagerException(Constants.Errors.SessionManager.LONG_TERM_CARD_VALIDATION,
					"Responder LongTerm card validation failed.");
		}

		if (cardsSet.getOneTimeCard() != null) {
			if (!validator.validate(cardsSet.getOneTimeCard())) {
				throw new SessionManagerException(Constants.Errors.SessionManager.ONE_TIME_CARD_VALIDATION,
						"Responder OneTime card validation failed.");
			}
		}

		CardEntry identityCardEntry = new CardEntry(identityCardId, identityPublicKeyData);
		CardEntry ltCardEntry = new CardEntry(cardsSet.getLongTermCard().getId(), longTermPublicKeyData);

		CardEntry otCardEntry = null;
		if (cardsSet.getOneTimeCard() != null && oneTimePublicKeyData != null) {
			otCardEntry = new CardEntry(cardsSet.getOneTimeCard().getId(), oneTimePublicKeyData);
		}

		Calendar cal = Calendar.getInstance();
		Date creationDate = cal.getTime();
		cal.add(Calendar.SECOND, this.sessionTtl);
		Date expirationDate = cal.getTime();

		SecureSession secureSession = this.sessionInitializer.initializeInitiatorSession(ephPrivateKey,
				identityCardEntry, ltCardEntry, otCardEntry, additionalData, expirationDate);

		this.saveSession(secureSession, creationDate, recipientCard.getId());

		this.addNewSessionToCache(secureSession, identityCardEntry.getIdentifier());

		return secureSession;
	}

	public void gentleReset() {
		log.fine(String.format("SessionManager: %s. Gentle reset started", this.identityCard.getId()));

		List<Entry<String, SessionState>> sessionStates = this.sessionStorageManager.getAllSessionsStates();

		for (Entry<String, SessionState> sessionState : sessionStates) {
			this.removeSessions(sessionState.getKey());
		}

		this.removeAllKeys();
	}

	/**
	 * @param cardId
	 *            the participant card identifier.
	 * @param sessionId
	 *            the participant session identifier.
	 */
	public void removeSession(String cardId, byte[] sessionId) {
		String sessionIdStr = ConvertionUtils.toBase64String(sessionId);
		log.fine(String.format("SessionManager: %s. Removing session with: %s, sessionId: %s",
				this.identityCard.getId(), cardId, sessionIdStr));

		this.removeSessionKeys(sessionId);
		this.sessionStorageManager.removeSessionState(cardId, sessionId);

		this.removeSessionFromCache(cardId, sessionId);
	}

	public void removeSessionFromCache(String cardId, byte[] sessionId) {
		SecureSession session = this.activeSessionCache.get(cardId);
		if (session != null) {
			if (Arrays.equals(session.getIdentifier(), sessionId)) {
				this.activeSessionCache.remove(cardId);
			}
			this.loadUpCache.remove(sessionId);
		}
	}

	private void addNewSessionToCache(SecureSession session, String cardId) {
		this.loadUpCache.put(session.getIdentifier(), session);
		this.activeSessionCache.put(cardId, session);
	}

	private SecureSession recoverSession(CardModel myIdentityCard, SessionState sessionState) {
		String sessionIdStr = ConvertionUtils.toBase64String(sessionState.getSessionId());
		log.fine(String.format("SessionManager: %s. Recovering session: %s", this.identityCard.getId(), sessionIdStr));

		SessionKeys sessionKeys = this.keyStorageManager.getSessionKeys(sessionState.getSessionId());

		return this.sessionInitializer.initializeSavedSession(sessionState.getSessionId(),
				sessionKeys.getEncryptionKey(), sessionKeys.getDecryptionKey(), sessionState.getAdditionalData(),
				sessionState.getExpirationDate());
	}

	private void removeAllKeys() {
		log.fine(String.format("SessionManager: %s. Removing all keys.", this.identityCard.getId()));

		this.keyStorageManager.gentleReset();
	}

	/**
	 * @param cardId
	 *            the participant card identifier.
	 */
	public void removeSessions(String cardId) {
		log.fine(String.format("SessionManager: %s. Removing sessions with: %s", this.identityCard.getId(), cardId));

		List<byte[]> sessionStatesIds = this.sessionStorageManager.getSessionStatesIds(cardId);
		for (byte[] sessionId : sessionStatesIds) {
			this.sessionStorageManager.removeSessionState(cardId, sessionId);
			this.removeSessionKeys(sessionId);
			this.removeSessionFromCache(cardId, sessionId);
		}
	}

	private void removeSessionKeys(String cardId) throws SessionManagerException {
		log.fine(
				String.format("SessionManager: %s. Removing session keys for: %s.", this.identityCard.getId(), cardId));

		try {
			this.keyStorageManager.removeOtPrivateKey(cardId);
		} catch (Exception e) {
			throw new SessionManagerException(Constants.Errors.SessionManager.REMOVING_OT_KEY,
					"Error while removing ot key", e);
		}
	}

	private void removeSessionKeys(byte[] sessionId) {
		String sessionIdStr = ConvertionUtils.toBase64String(sessionId);
		log.fine(String.format("SessionManager: %s. Removing session keys for: %s.", this.identityCard.getId(),
				sessionIdStr));

		this.keyStorageManager.removeSessionKeys(sessionId);
	}

}
