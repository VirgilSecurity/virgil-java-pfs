package com.virgilsecurity.sdk.securechat.migration.v1_1;

import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Logger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.securechat.Constants;
import com.virgilsecurity.sdk.securechat.KeyStorageManager;
import com.virgilsecurity.sdk.securechat.UserDataStorage;
import com.virgilsecurity.sdk.securechat.exceptions.MigrationException;
import com.virgilsecurity.sdk.securechat.keystorage.JsonFileKeyStorage;
import com.virgilsecurity.sdk.securechat.keystorage.KeyAttrs;
import com.virgilsecurity.sdk.securechat.keystorage.KeyStorage;
import com.virgilsecurity.sdk.securechat.model.CardEntry;
import com.virgilsecurity.sdk.securechat.model.Optional;
import com.virgilsecurity.sdk.securechat.session.SecureSession;
import com.virgilsecurity.sdk.securechat.session.SessionInitializer;
import com.virgilsecurity.sdk.securechat.session.SessionManager;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.VirgilKeyEntry;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

public class MigrationV1_1 {
	private static class ByteArrayToBase64TypeAdapter implements JsonSerializer<byte[]> {

		public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
			return new JsonPrimitive(ConvertionUtils.toBase64String(src));
		}
	}

	private class InitiatorSessionState {
		@SerializedName("creation_date")
		private Date creationDate;

		@SerializedName("expiration_date")
		private Date expirationDate;

		@SerializedName("session_id")
		private byte[] sessionId;

		@Optional
		@SerializedName("additional_data")
		private byte[] additionalData;

		@SerializedName("eph_key_name")
		private String ephKeyName;

		@SerializedName("recipient_card_id")
		private String recipientCardId;

		@SerializedName("recipient_public_key")
		private byte[] recipientPublicKey;

		@SerializedName("recipient_long_term_card_id")
		private String recipientLongTermCardId;

		@SerializedName("recipient_long_term_public_key")
		private byte[] recipientLongTermPublicKey;

		@Optional
		@SerializedName("recipient_one_time_card_id")
		private String recipientOneTimeCardId;

		@Optional
		@SerializedName("recipient_one_time_public_key")
		private byte[] recipientOneTimePublicKey;

		/**
		 * 
		 * Create new instance of {@link InitiatorSessionState}
		 * 
		 * @param creationDate
		 * @param expirationDate
		 * @param sessionId
		 * @param additionalData
		 * @param ephKeyName
		 * @param recipientCardId
		 * @param recipientPublicKey
		 * @param recipientLongTermCardId
		 * @param recipientLongTermPublicKey
		 * @param recipientOneTimeCardId
		 * @param recipientOneTimePublicKey
		 */
		public InitiatorSessionState(Date creationDate, Date expirationDate, byte[] sessionId, byte[] additionalData,
				String ephKeyName, String recipientCardId, byte[] recipientPublicKey, String recipientLongTermCardId,
				byte[] recipientLongTermPublicKey, String recipientOneTimeCardId, byte[] recipientOneTimePublicKey) {
			super();
			this.creationDate = creationDate;
			this.expirationDate = expirationDate;
			this.sessionId = sessionId;
			this.additionalData = additionalData;
			this.ephKeyName = ephKeyName;
			this.recipientCardId = recipientCardId;
			this.recipientPublicKey = recipientPublicKey;
			this.recipientLongTermCardId = recipientLongTermCardId;
			this.recipientLongTermPublicKey = recipientLongTermPublicKey;
			this.recipientOneTimeCardId = recipientOneTimeCardId;
			this.recipientOneTimePublicKey = recipientOneTimePublicKey;
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
		 * @return the ephKeyName
		 */
		public String getEphKeyName() {
			return ephKeyName;
		}

		/**
		 * @return the expirationDate
		 */
		public Date getExpirationDate() {
			return expirationDate;
		}

		/**
		 * @return the recipientCardId
		 */
		public String getRecipientCardId() {
			return recipientCardId;
		}

		/**
		 * @return the recipientLongTermCardId
		 */
		public String getRecipientLongTermCardId() {
			return recipientLongTermCardId;
		}

		/**
		 * @return the recipientLongTermPublicKey
		 */
		public byte[] getRecipientLongTermPublicKey() {
			return recipientLongTermPublicKey;
		}

		/**
		 * @return the recipientOneTimeCardId
		 */
		public String getRecipientOneTimeCardId() {
			return recipientOneTimeCardId;
		}

		/**
		 * @return the recipientOneTimePublicKey
		 */
		public byte[] getRecipientOneTimePublicKey() {
			return recipientOneTimePublicKey;
		}

		/**
		 * @return the recipientPublicKey
		 */
		public byte[] getRecipientPublicKey() {
			return recipientPublicKey;
		}

		/**
		 * @return the sessionId
		 */
		public byte[] getSessionId() {
			return sessionId;
		}

		/**
		 * @param additionalData
		 *            the additionalData to set
		 */
		public void setAdditionalData(byte[] additionalData) {
			this.additionalData = additionalData;
		}

		/**
		 * @param creationDate
		 *            the creationDate to set
		 */
		public void setCreationDate(Date creationDate) {
			this.creationDate = creationDate;
		}

		/**
		 * @param ephKeyName
		 *            the ephKeyName to set
		 */
		public void setEphKeyName(String ephKeyName) {
			this.ephKeyName = ephKeyName;
		}

		/**
		 * @param expirationDate
		 *            the expirationDate to set
		 */
		public void setExpirationDate(Date expirationDate) {
			this.expirationDate = expirationDate;
		}

		/**
		 * @param recipientCardId
		 *            the recipientCardId to set
		 */
		public void setRecipientCardId(String recipientCardId) {
			this.recipientCardId = recipientCardId;
		}

		/**
		 * @param recipientLongTermCardId
		 *            the recipientLongTermCardId to set
		 */
		public void setRecipientLongTermCardId(String recipientLongTermCardId) {
			this.recipientLongTermCardId = recipientLongTermCardId;
		}

		/**
		 * @param recipientLongTermPublicKey
		 *            the recipientLongTermPublicKey to set
		 */
		public void setRecipientLongTermPublicKey(byte[] recipientLongTermPublicKey) {
			this.recipientLongTermPublicKey = recipientLongTermPublicKey;
		}

		/**
		 * @param recipientOneTimeCardId
		 *            the recipientOneTimeCardId to set
		 */
		public void setRecipientOneTimeCardId(String recipientOneTimeCardId) {
			this.recipientOneTimeCardId = recipientOneTimeCardId;
		}

		/**
		 * @param recipientOneTimePublicKey
		 *            the recipientOneTimePublicKey to set
		 */
		public void setRecipientOneTimePublicKey(byte[] recipientOneTimePublicKey) {
			this.recipientOneTimePublicKey = recipientOneTimePublicKey;
		}

		/**
		 * @param recipientPublicKey
		 *            the recipientPublicKey to set
		 */
		public void setRecipientPublicKey(byte[] recipientPublicKey) {
			this.recipientPublicKey = recipientPublicKey;
		}

		/**
		 * @param sessionId
		 *            the sessionId to set
		 */
		public void setSessionId(byte[] sessionId) {
			this.sessionId = sessionId;
		}

	}

	private class ResponderSessionState {
		@SerializedName("creation_date")
		private Date creationDate;
		@SerializedName("expiration_date")
		private Date expirationDate;
		@SerializedName("session_id")
		private byte[] sessionId;
		@Optional
		@SerializedName("additional_data")
		private byte[] additionalData;
		@SerializedName("eph_public_key_data")
		private byte[] ephPublicKeyData;
		@SerializedName("recipient_identity_card_id")
		private String recipientIdentityCardId;
		@SerializedName("recipient_identity_public_key")
		private byte[] recipientIdentityPublicKey;
		@SerializedName("recipient_long_term_card_id")
		private String recipientLongTermCardId;
		@SerializedName("recipient_one_time_card_id")
		private String recipientOneTimeCardId;

		public ResponderSessionState(Date creationDate, Date expirationDate, byte[] sessionId, byte[] additionalData,
				byte[] ephPublicKeyData, String recipientIdentityCardId, byte[] recipientIdentityPublicKey,
				String recipientLongTermCardId, String recipientOneTimeCardId) {
			super();
			this.creationDate = creationDate;
			this.expirationDate = expirationDate;
			this.sessionId = sessionId;
			this.additionalData = additionalData;
			this.ephPublicKeyData = ephPublicKeyData;
			this.recipientIdentityCardId = recipientIdentityCardId;
			this.recipientIdentityPublicKey = recipientIdentityPublicKey;
			this.recipientLongTermCardId = recipientLongTermCardId;
			this.recipientOneTimeCardId = recipientOneTimeCardId;
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
		 * @return the ephPublicKeyData
		 */
		public byte[] getEphPublicKeyData() {
			return ephPublicKeyData;
		}

		/**
		 * @return the expirationDate
		 */
		public Date getExpirationDate() {
			return expirationDate;
		}

		/**
		 * @return the recipientIdentityCardId
		 */
		public String getRecipientIdentityCardId() {
			return recipientIdentityCardId;
		}

		/**
		 * @return the recipientIdentityPublicKey
		 */
		public byte[] getRecipientIdentityPublicKey() {
			return recipientIdentityPublicKey;
		}

		/**
		 * @return the recipientLongTermCardId
		 */
		public String getRecipientLongTermCardId() {
			return recipientLongTermCardId;
		}

		/**
		 * @return the recipientOneTimeCardId
		 */
		public String getRecipientOneTimeCardId() {
			return recipientOneTimeCardId;
		}

		/**
		 * @return the sessionId
		 */
		public byte[] getSessionId() {
			return sessionId;
		}

		/**
		 * @param additionalData
		 *            the additionalData to set
		 */
		public void setAdditionalData(byte[] additionalData) {
			this.additionalData = additionalData;
		}

		/**
		 * @param creationDate
		 *            the creationDate to set
		 */
		public void setCreationDate(Date creationDate) {
			this.creationDate = creationDate;
		}

		/**
		 * @param ephPublicKeyData
		 *            the ephPublicKeyData to set
		 */
		public void setEphPublicKeyData(byte[] ephPublicKeyData) {
			this.ephPublicKeyData = ephPublicKeyData;
		}

		/**
		 * @param expirationDate
		 *            the expirationDate to set
		 */
		public void setExpirationDate(Date expirationDate) {
			this.expirationDate = expirationDate;
		}

		/**
		 * @param recipientIdentityCardId
		 *            the recipientIdentityCardId to set
		 */
		public void setRecipientIdentityCardId(String recipientIdentityCardId) {
			this.recipientIdentityCardId = recipientIdentityCardId;
		}

		/**
		 * @param recipientIdentityPublicKey
		 *            the recipientIdentityPublicKey to set
		 */
		public void setRecipientIdentityPublicKey(byte[] recipientIdentityPublicKey) {
			this.recipientIdentityPublicKey = recipientIdentityPublicKey;
		}

		/**
		 * @param recipientLongTermCardId
		 *            the recipientLongTermCardId to set
		 */
		public void setRecipientLongTermCardId(String recipientLongTermCardId) {
			this.recipientLongTermCardId = recipientLongTermCardId;
		}

		/**
		 * @param recipientOneTimeCardId
		 *            the recipientOneTimeCardId to set
		 */
		public void setRecipientOneTimeCardId(String recipientOneTimeCardId) {
			this.recipientOneTimeCardId = recipientOneTimeCardId;
		}

		/**
		 * @param sessionId
		 *            the sessionId to set
		 */
		public void setSessionId(byte[] sessionId) {
			this.sessionId = sessionId;
		}

	}

	private class SessionStates {
		private Map<String, InitiatorSessionState> initiatorSessionStates;
		private Map<String, ResponderSessionState> responderSessionState;

		/**
		 * @param initiatorSessionStates
		 * @param responderSessionState
		 */
		public SessionStates(Map<String, InitiatorSessionState> initiatorSessionStates,
				Map<String, ResponderSessionState> responderSessionState) {
			super();
			this.initiatorSessionStates = initiatorSessionStates;
			this.responderSessionState = responderSessionState;
		}

		/**
		 * @return the initiatorSessionStates
		 */
		public Map<String, InitiatorSessionState> getInitiatorSessionStates() {
			return initiatorSessionStates;
		}

		/**
		 * @return the responderSessionState
		 */
		public Map<String, ResponderSessionState> getResponderSessionState() {
			return responderSessionState;
		}

	}

	private static final Logger log = Logger.getLogger(MigrationV1_1.class.getName());
	private static final Set<String> INITIATOR_SESSION_STATE_FIELDS;
	private static final Set<String> RESPONDER_SESSION_STATE_FIELDS;
	static {
		INITIATOR_SESSION_STATE_FIELDS = Collections
				.unmodifiableSet(getSerializedNameValues(InitiatorSessionState.class));
		RESPONDER_SESSION_STATE_FIELDS = Collections
				.unmodifiableSet(getSerializedNameValues(ResponderSessionState.class));
	}

	private static Set<String> getSerializedNameValues(Class<?> clazz) {
		Set<String> fields = new HashSet<>();
		for (Field field : clazz.getDeclaredFields()) {
			if (field.isAnnotationPresent(Optional.class)) {
				continue;
			}
			SerializedName serializedName = field.getAnnotation(SerializedName.class);
			if (serializedName != null) {
				fields.add(serializedName.value());
			}
		}
		return fields;
	}

	private static String getSuiteName(String cardId) {
		return "VIRGIL.DEFAULTS." + cardId;
	}

	public static boolean isInitiatorSessionState(String json) {
		JsonObject jsObj = (JsonObject) new JsonParser().parse(json);
		for (String fieldName : INITIATOR_SESSION_STATE_FIELDS) {
			if (!jsObj.has(fieldName)) {
				return false;
			}
		}
		return true;
	}

	public static boolean isResponderSessionState(String json) {
		JsonObject jsObj = (JsonObject) new JsonParser().parse(json);
		for (String fieldName : RESPONDER_SESSION_STATE_FIELDS) {
			if (!jsObj.has(fieldName)) {
				return false;
			}
		}
		return true;
	}

	private Crypto crypto;

	private PrivateKey identityPrivateKey;

	private CardModel identityCard;

	private KeyStorage keyStorage;

	private KeyStorageManager keyStorageManager;

	private UserDataStorage dataStorage;

	private SessionInitializer sessionInitializer;

	private SessionManager sessionManager;

	/**
	 * Create new instance of {@link MigrationV1_1}
	 * 
	 * @param crypto
	 *            The crypto.
	 * @param identityPrivateKey
	 *            The identity private key.
	 * @param identityCard
	 *            The Virgil Card of identity.
	 * @param keyStorage
	 *            The key storage.
	 * @param keyStorageManager
	 *            The key storage manager.
	 * @param storage
	 *            The user data storage.
	 * @param sessionInitializer
	 *            The session initializer.
	 * @param sessionManager
	 *            The session manager.
	 */
	public MigrationV1_1(Crypto crypto, PrivateKey identityPrivateKey, CardModel identityCard, KeyStorage keyStorage,
			KeyStorageManager keyStorageManager, UserDataStorage storage, SessionInitializer sessionInitializer,
			SessionManager sessionManager) {
		super();
		this.crypto = crypto;
		this.identityPrivateKey = identityPrivateKey;
		this.identityCard = identityCard;
		this.keyStorage = keyStorage;
		this.keyStorageManager = keyStorageManager;
		this.dataStorage = storage;
		this.sessionInitializer = sessionInitializer;
		this.sessionManager = sessionManager;
	}

	private String extractCardId(String sessionName) {
		if (sessionName == null) {
			return null;
		}
		return sessionName.replace("VIRGIL.SESSION.", "");
	}

	private String extractLtCardId(String ltkeyEntryName) {
		String oldChar = String.format("VIRGIL.OWNER=%s.LT_KEY.", this.identityCard.getId());
		return ltkeyEntryName.replace(oldChar, "");
	}

	private String extractOtCardId(String otkeyEntryName) {
		String oldChar = String.format("VIRGIL.OWNER=%s.OT_KEY.", this.identityCard.getId());
		return otkeyEntryName.replace(oldChar, "");
	}

	private SessionStates getAllSessions() throws MigrationException {
		Map<String, InitiatorSessionState> initiators = new HashMap<>();
		Map<String, ResponderSessionState> responders = new HashMap<>();

		for (Entry<String, String> entry : this.dataStorage.getAllData("VIRGIL.DEFAULTS." + this.identityCard.getId())
				.entrySet()) {
			String cardId = this.extractCardId(entry.getKey());
			if (StringUtils.isBlank(cardId)) {
				continue;
			}

			String json = entry.getValue();
			if (isInitiatorSessionState(json)) {
				initiators.put(cardId, ConvertionUtils.getGson().fromJson(json, InitiatorSessionState.class));
			} else if (isResponderSessionState(json)) {
				responders.put(cardId, ConvertionUtils.getGson().fromJson(json, ResponderSessionState.class));
			} else {
				throw new MigrationException(Constants.Errors.Migration.V1_1.UNKNOWN_SESSION_STATE,
						"Found unknown session state while migration to v1.1");
			}
		}

		return new SessionStates(initiators, responders);
	}

	private KeyEntry getEphPrivateKey(String name) {
		return this.keyStorage.load(name);
	}

	private String getServiceInfoEntryName() {
		return String.format("VIRGIL.SERVICE.INFO.%s", this.identityCard.getId());
	}

	public void migrate() throws MigrationException {
		// Get sessions
		SessionStates sessionStates = this.getAllSessions();
		Map<String, InitiatorSessionState> initiators = sessionStates.getInitiatorSessionStates();
		Map<String, ResponderSessionState> responders = sessionStates.getResponderSessionState();

		// Migrate initiator's sessions
		for (Entry<String, InitiatorSessionState> initiatorEntry : initiators.entrySet()) {
			InitiatorSessionState initiator = initiatorEntry.getValue();

			log.fine("Migrate session: " + ConvertionUtils.toBase64String(initiator.sessionId));

			String ephKeyName = initiator.getEphKeyName();
			KeyEntry ephKeyEntry = this.getEphPrivateKey(ephKeyName);
			PrivateKey ephPrivateKey;
			try {
				ephPrivateKey = this.crypto.importPrivateKey(ephKeyEntry.getValue());
			} catch (Exception e) {
				throw new MigrationException(Constants.Errors.Migration.V1_1.IMPORTING_EPH_PRIVATE_KEY,
						"Error importing Eph private key while migrating to 1.1.");
			}

			CardEntry recipientIdCard = new CardEntry(initiator.getRecipientCardId(),
					initiator.getRecipientPublicKey());
			CardEntry recipientLtCard = new CardEntry(initiator.getRecipientLongTermCardId(),
					initiator.getRecipientLongTermPublicKey());

			CardEntry recipientOtCard = null;
			if (!StringUtils.isBlank(initiator.recipientOneTimeCardId)) {
				recipientOtCard = new CardEntry(initiator.getRecipientOneTimeCardId(),
						initiator.getRecipientOneTimePublicKey());
			}

			SecureSession secureSession = this.sessionInitializer.initializeInitiatorSession(ephPrivateKey,
					recipientIdCard, recipientLtCard, recipientOtCard, initiator.getAdditionalData(),
					initiator.getExpirationDate());

			this.sessionManager.saveSession(secureSession, initiator.getCreationDate(),
					recipientIdCard.getIdentifier());

			this.removeEphPrivateKey(ephKeyName);
		}

		// Migrate responder's sessions
		for (Entry<String, ResponderSessionState> responderEntry : responders.entrySet()) {
			ResponderSessionState responder = responderEntry.getValue();

			PrivateKey ltPrivateKey;
			try {
				ltPrivateKey = this.keyStorageManager.getLtPrivateKey(responder.getRecipientLongTermCardId());
			} catch (Exception e) {
				throw new MigrationException(Constants.Errors.Migration.V1_1.IMPORTING_LT_PRIVATE_KEY,
						"Error importing long term private key while migrating to 1.1.");
			}

			PrivateKey otPrivateKey = null;
			if (!StringUtils.isBlank(responder.getRecipientOneTimeCardId())) {
				try {
					otPrivateKey = this.keyStorageManager.getOtPrivateKey(responder.getRecipientOneTimeCardId());
				} catch (Exception e) {
					throw new MigrationException(Constants.Errors.Migration.V1_1.IMPORTING_OT_PRIVATE_KEY,
							"Error importing one time private key while migrating to 1.1.");
				}
			}

			CardEntry initiatorCardEntry = new CardEntry(responder.getRecipientIdentityCardId(),
					responder.getRecipientIdentityPublicKey());

			SecureSession secureSession = this.sessionInitializer.initializeResponderSession(initiatorCardEntry,
					this.identityPrivateKey, ltPrivateKey, otPrivateKey, responder.getEphPublicKeyData(),
					responder.getAdditionalData(), responder.getExpirationDate());

			this.sessionManager.saveSession(secureSession, responder.getCreationDate(),
					initiatorCardEntry.getIdentifier());

			if (!StringUtils.isBlank(responder.getRecipientOneTimeCardId())) {
				this.keyStorageManager.removeOtPrivateKey(responder.getRecipientOneTimeCardId());
			}
		}

		// Remove Service info
		this.removeServiceInfoEntry();

		// Remove old session
		this.removeAllSessions();
	}

	public void migrateKeyStorage() {
		if (this.keyStorage instanceof JsonFileKeyStorage) {
			JsonFileKeyStorage jsonFileKeyStorage = (JsonFileKeyStorage) this.keyStorage;
			try {
				GsonBuilder builder = new GsonBuilder();
				Gson gson = builder.registerTypeHierarchyAdapter(byte[].class, new ByteArrayToBase64TypeAdapter())
						.disableHtmlEscaping().setDateFormat("yyyy-MM-dd HH:mm:ss.SSSS").create();
				jsonFileKeyStorage.setGson(gson);

				List<KeyAttrs> keysAttrs = jsonFileKeyStorage.getAllKeysAttrs();
				if (!keysAttrs.isEmpty()) {
					KeyEntry keyEntry = new VirgilKeyEntry(UUID.randomUUID().toString(), new byte[0]);
					jsonFileKeyStorage.store(keyEntry);
					jsonFileKeyStorage.setGson(null);
					jsonFileKeyStorage.delete(keyEntry.getName());
				}
			} finally {
				jsonFileKeyStorage.setGson(null);
			}
		}
	}

	private void removeAllSessions() {
		this.dataStorage.removeAll(MigrationV1_1.getSuiteName(this.identityCard.getId()));
	}

	private void removeEphPrivateKey(String name) {
		this.keyStorage.delete(name);
	}

	private void removeServiceInfoEntry() {
		String entryName = this.getServiceInfoEntryName();
		if (this.keyStorage.exists(entryName)) {
			this.keyStorage.delete(this.getServiceInfoEntryName());
		}
	}

}
