package com.virgilsecurity.sdk.securechat;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.VirgilClient;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.pfs.BaseIT;
import com.virgilsecurity.sdk.pfs.VirgilPFSClient;
import com.virgilsecurity.sdk.pfs.VirgilPFSClientContext;
import com.virgilsecurity.sdk.pfs.model.response.OtcCountResponse;
import com.virgilsecurity.sdk.securechat.keystorage.JsonFileKeyStorage;
import com.virgilsecurity.sdk.securechat.keystorage.KeyAttrs;
import com.virgilsecurity.sdk.securechat.keystorage.KeyStorage;

public class EphemeralCardsReplenisherTest extends BaseIT {

	private VirgilClient virgilClient;
	private VirgilPFSClient pfsClient;
	private KeyStorageManager keyStorageManager;
	private EphemeralCardsReplenisher cardsReplenisher;

	@Before
	public void setUp() throws MalformedURLException, CryptoException {
		// Initialize Crypto
		crypto = new VirgilCrypto();

		// Prepare context
		VirgilPFSClientContext ctx = new VirgilPFSClientContext(APP_TOKEN);

		String url = getPropertyByName("CARDS_SERVICE");
		if (StringUtils.isNotBlank(url)) {
			ctx.setCardsServiceURL(new URL(url));
		}
		url = getPropertyByName("RO_CARDS_SERVICE");
		if (StringUtils.isNotBlank(url)) {
			ctx.setReadOnlyCardsServiceURL(new URL(url));
		}
		url = getPropertyByName("IDENTITY_SERVICE");
		if (StringUtils.isNotBlank(url)) {
			ctx.setIdentityServiceURL(new URL(url));
		}
		url = getPropertyByName("EPH_SERVICE");
		if (StringUtils.isNotBlank(url)) {
			ctx.setEphemeralServiceURL(new URL(url));
		}

		appKey = crypto.importPrivateKey(APP_PRIVATE_KEY.getBytes(), APP_PRIVATE_KEY_PASSWORD);

		virgilClient = new VirgilClient(ctx);
		pfsClient = new VirgilPFSClient(ctx);
	}

	@Test
	public void addCards() {
		KeyPair keyPair = crypto.generateKeys();

		PublishCardRequest identityRequest = instantiateCreateCardRequest(keyPair);

		CardModel card = virgilClient.publishCard(identityRequest);
		initializeReplenisher(keyPair.getPrivateKey(), card);

		Map<String, List<KeyAttrs>> keyAttrs = keyStorageManager.getAllKeysAttrs();
		assertTrue(keyAttrs.get("ot").isEmpty());
		assertTrue(keyAttrs.get("lt").isEmpty());

		String cardId = card.getId();
		int desiredNumber1 = 0;
		int desiredNumber2 = 10;
		int desiredNumber3 = 10;

		cardsReplenisher.addCards(true, desiredNumber1);
		keyAttrs = keyStorageManager.getAllKeysAttrs();
		assertEquals(desiredNumber1, keyAttrs.get("ot").size());
		assertEquals(1, keyAttrs.get("lt").size());

		OtcCountResponse status = pfsClient.getOtcCount(cardId);
		assertEquals(desiredNumber1, status.getActive());

		cardsReplenisher.addCards(true, desiredNumber2);
		keyAttrs = keyStorageManager.getAllKeysAttrs();
		assertEquals(desiredNumber1 + desiredNumber2, keyAttrs.get("ot").size());
		assertEquals(2, keyAttrs.get("lt").size());

		status = pfsClient.getOtcCount(cardId);
		assertEquals(desiredNumber1 + desiredNumber2, status.getActive());

		cardsReplenisher.addCards(false, desiredNumber3);
		keyAttrs = keyStorageManager.getAllKeysAttrs();
		assertEquals(desiredNumber1 + desiredNumber2 + desiredNumber3, keyAttrs.get("ot").size());
		assertEquals(2, keyAttrs.get("lt").size());

		status = pfsClient.getOtcCount(cardId);
		assertEquals(desiredNumber1 + desiredNumber2 + desiredNumber3, status.getActive());
	}

	private void initializeReplenisher(PrivateKey privateKey, CardModel card) {
		KeyStorage keyStorage = new JsonFileKeyStorage(System.getProperty("java.io.tmpdir"),
				UUID.randomUUID().toString());
		this.keyStorageManager = new KeyStorageManager(this.crypto, keyStorage, card.getId());
		this.cardsReplenisher = new EphemeralCardsReplenisher(this.crypto, privateKey, card.getId(), this.pfsClient,
				this.keyStorageManager);
	}

}
