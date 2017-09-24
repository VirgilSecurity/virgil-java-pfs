package com.virgilsecurity.sdk.securechat;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.logging.Logger;

import com.virgilsecurity.sdk.client.RequestSigner;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.pfs.VirgilPFSClient;
import com.virgilsecurity.sdk.pfs.model.request.CreateEphemeralCardRequest;
import com.virgilsecurity.sdk.securechat.KeyStorageManager.HelperKeyEntry;

public class EphemeralCardsReplenisher {
	private static final Logger log = Logger.getLogger(EphemeralCardsReplenisher.class.getName());
	public static final String IDENTITY_TYPE = "identity_card_id";

	private Crypto crypto;
	private PrivateKey identityPrivateKey;
	private String identityCardId;
	private VirgilPFSClient client;
	private KeyStorageManager keyStorageManager;

	public EphemeralCardsReplenisher(Crypto crypto, PrivateKey identityPrivateKey, String identityCardId,
			VirgilPFSClient client, KeyStorageManager keyStorageManager) {
		this.crypto = crypto;
		this.identityPrivateKey = identityPrivateKey;
		this.identityCardId = identityCardId;
		this.client = client;
		this.keyStorageManager = keyStorageManager;
	}

	private Entry<CreateEphemeralCardRequest, String> generateRequest(KeyPair keyPair, boolean isLtc) {
		String identity = this.identityCardId;

		byte[] publicKeyData = this.crypto.exportPublicKey(keyPair.getPublicKey());
		CreateEphemeralCardRequest request = new CreateEphemeralCardRequest(identity, IDENTITY_TYPE, publicKeyData);

		RequestSigner requestSigner = new RequestSigner(this.crypto);
		String cardId = requestSigner.getCardId(request);
		requestSigner.authoritySign(request, this.identityCardId, this.identityPrivateKey);

		return new AbstractMap.SimpleEntry<CreateEphemeralCardRequest, String>(request, cardId);
	}

	public void addCards(boolean includeLtcCard, int numberOfOtcCards) {
		log.fine(String.format("Adding %d cards for: %s, include lt: %b", numberOfOtcCards, this.identityCardId,
				includeLtcCard));

		List<KeyStorageManager.HelperKeyEntry> otcKeys = new ArrayList<>(numberOfOtcCards);
		List<CreateEphemeralCardRequest> otcCardsRequests = new ArrayList<>(numberOfOtcCards);

		for (int i = 0; i < numberOfOtcCards; i++) {
			KeyPair keyPair = crypto.generateKeys();

			Entry<CreateEphemeralCardRequest, String> entry = generateRequest(keyPair, false);
			otcCardsRequests.add(entry.getKey());

			HelperKeyEntry keyEntry = new KeyStorageManager.HelperKeyEntry(keyPair.getPrivateKey(), entry.getValue());
			otcKeys.add(keyEntry);
		}

		KeyStorageManager.HelperKeyEntry ltcKey = null;
		CreateEphemeralCardRequest ltcCardRequest = null;
		if (includeLtcCard) {
			KeyPair keyPair = this.crypto.generateKeys();
			Entry<CreateEphemeralCardRequest, String> entry = generateRequest(keyPair, true);
			ltcCardRequest = entry.getKey();

			ltcKey = new KeyStorageManager.HelperKeyEntry(keyPair.getPrivateKey(), entry.getValue());
		}

		this.keyStorageManager.saveKeys(otcKeys, ltcKey);

		// TODO extend exception handling

		if (ltcCardRequest != null) {
			this.client.bootstrapCardsSet(this.identityCardId, ltcCardRequest, otcCardsRequests);
		} else if (!otcCardsRequests.isEmpty()) {
			this.client.createOneTimeCards(this.identityCardId, otcCardsRequests);
		}
	}
}
