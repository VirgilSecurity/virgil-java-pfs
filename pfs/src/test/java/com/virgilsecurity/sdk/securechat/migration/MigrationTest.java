package com.virgilsecurity.sdk.securechat.migration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.device.DefaultDeviceManager;
import com.virgilsecurity.sdk.pfs.BaseIT;
import com.virgilsecurity.sdk.pfs.VirgilPFSClientContext;
import com.virgilsecurity.sdk.securechat.KeyStorageManager;
import com.virgilsecurity.sdk.securechat.SecureChat;
import com.virgilsecurity.sdk.securechat.SecureChat.Version;
import com.virgilsecurity.sdk.securechat.SecureChatContext;
import com.virgilsecurity.sdk.securechat.SessionStorageManager;
import com.virgilsecurity.sdk.securechat.TestUtils;
import com.virgilsecurity.sdk.securechat.UserDataStorage;
import com.virgilsecurity.sdk.securechat.exceptions.MigrationException;
import com.virgilsecurity.sdk.securechat.exceptions.SessionManagerException;
import com.virgilsecurity.sdk.securechat.impl.DefaultUserDataStorage;
import com.virgilsecurity.sdk.securechat.keystorage.JsonFileKeyStorage;
import com.virgilsecurity.sdk.securechat.migration.v1_1.MigrationV1_1;
import com.virgilsecurity.sdk.securechat.session.SessionInitializer;
import com.virgilsecurity.sdk.securechat.session.SessionManager;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StreamUtils;

public class MigrationTest extends BaseIT {
	private SecureChat secureChat;
	private CardModel card;
	private UserDataStorage storage;
	private Crypto crypto;
	private PrivateKey privateKey;
	private JsonFileKeyStorage keyStorage;

	@Before
	public void setUp() throws CryptoException, MalformedURLException {
		// Initialize Crypto
		this.crypto = new VirgilCrypto();

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

		String cardStr = "eyJpZCI6ImUwYTRkYjI0MTg2NmZhZjI0NDk0ZWI3M2ZiNzM5YmFlZTJlMmE2ZmIyMDkyMTFlNTNlNjA2ODY2YWI0NmFiYjEiLCJjb250ZW50X3NuYXBzaG90IjoiZXlKcFpHVnVkR2wwZVNJNkltRnNhV05sT1dFM1kyTTJaR1F0WWpVd09DMDBZekV3TFdKa09ESXRZV1F5TVRCbVpURTVZV1ZqSWl3aWFXUmxiblJwZEhsZmRIbHdaU0k2SW5WelpYSnVZVzFsSWl3aWNIVmliR2xqWDJ0bGVTSTZJazFEYjNkQ1VWbEVTekpXZDBGNVJVRnFNalpQWm5WbFJrUkNNQ3RJZEVwVWEyVlFla3BZZGxKemFVNTBXbEpLTjBvMlpUSXhNekl5TjFGRlBTSXNJbk5qYjNCbElqb2lZWEJ3YkdsallYUnBiMjRpZlE9PSIsIm1ldGEiOnsic2lnbnMiOnsiMWVmMmU0NWY2MTAwNzkyYmM2MDA4MjhmMTQyNWIyN2NlNzY1NWE4MDU0MzExOGYzNzViZDg5NGQ3MzEzYWEwMCI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFMR2VqYzllMUNQWFZRMWFPYkN2V1BHUmNUMXYyMVJ5dDlYcmxmZUU4ZTRGUmdBKzYvYUNXWVVZQ2RaZEVIdXloNTVtWDBadE9PNGZuNHZmdTZXMEVBQT0iLCJlMGE0ZGIyNDE4NjZmYWYyNDQ5NGViNzNmYjczOWJhZWUyZTJhNmZiMjA5MjExZTUzZTYwNjg2NmFiNDZhYmIxIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUhVemg3VmsvamZ2VnN6Ukl6cXRQcEY1NndaMnY5K3p2QUc4M1h2SWNRK0VNdlUxM1ZTTWxLWlJZZmorbk5TS2NkeXdaNU9VRWlRWm5Cd2U2UHFjcGdFPSIsImU2ODBiZWY4N2JhNzVkMzMxYjBhMDJiZmE2YTIwZjAyZWI1YzViYTliYzk2ZmM2MWNhNTk1NDA0YjEwMDI2ZjQiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRSmFoV3duNjArZW1DZ2cySW41dFI3MlBsZEFORXY2QlVNRWh4UUg1YWpLWlpmYjExSFR6RldtNE5oTnRXS3VSbjlIbEJ5RktLS2o2NXUweFNnQ2dNUW89In0sImNyZWF0ZWRfYXQiOiJPY3QgOCwgMjAxNyA0OjI1OjMyIFBNIiwiY2FyZF92ZXJzaW9uIjoiNC4wIn19";
		this.card = TestUtils.importCard(cardStr);

		byte[] privateKeyData = ConvertionUtils
				.base64ToBytes("MC4CAQAwBQYDK2VwBCIEINS3oTTn4VaxMcpGvLMlIvEDppr7Vn+kIgC0qZ5gKcqj");
		this.privateKey = crypto.importPrivateKey(privateKeyData);

		this.storage = new DefaultUserDataStorage();
		this.storage.addData("VIRGIL.DEFAULTS.e0a4db241866faf24494eb73fb739baee2e2a6fb209211e53e606866ab46abb1",
				"VIRGIL.SESSION.bb81ef619008587d1caf03bdd2ea9cd087a4cfcd68d1956f6888b26b5ffa58e0",
				"{\"eph_key_name\":\"VIRGIL.OWNER.e0a4db241866faf24494eb73fb739baee2e2a6fb209211e53e606866ab46abb1.EPH_KEY.bb81ef619008587d1caf03bdd2ea9cd087a4cfcd68d1956f6888b26b5ffa58e0\",\"recipient_card_id\":\"bb81ef619008587d1caf03bdd2ea9cd087a4cfcd68d1956f6888b26b5ffa58e0\",\"recipient_public_key\":\"MCowBQYDK2VwAyEA2qZUBDDmyU/UO4Qt50RqYTlbkrE9colKz24GYJktytw=\",\"recipient_long_term_card_id\":\"805071fec2c6cb109606c756062d260bbe05c183209f02fdd027baf1e51ed1b8\",\"recipient_long_term_public_key\":\"MCowBQYDK2VwAyEAU6N2xecXbCsXhLx0r+zvqN80QrT57gIUHMQhNpq7mSc=\",\"recipient_one_time_card_id\":\"2118d9be7efa2b4b5a6f50bb8b984a5dcc9f2f9bfe2cc8ca8d0f17c6e2d641fc\",\"recipient_one_time_public_key\":\"MCowBQYDK2VwAyEAlTQBDCz9b85ixuJOnIAd0Ikxbf6GVLouFTHcnFWDjpo=\",\"creation_date\":\"Oct 8, 2017 4:25:35 PM\",\"expiration_date\":\"Oct 9, 2017 4:25:35 PM\",\"session_id\":\"MTLQvU82MN8Fc/bKLkZDDRAfMTtBiOiQoTgMeGRl644=\",\"additional_data\":null}");
		this.storage.addData("VIRGIL.DEFAULTS.e0a4db241866faf24494eb73fb739baee2e2a6fb209211e53e606866ab46abb1",
				"VIRGIL.SESSION.ca851674e1ca64e464896c4a11134b14636194936e64ab2299c6e0f726082290",
				"{\"eph_key_name\":\"VIRGIL.OWNER.e0a4db241866faf24494eb73fb739baee2e2a6fb209211e53e606866ab46abb1.EPH_KEY.ca851674e1ca64e464896c4a11134b14636194936e64ab2299c6e0f726082290\",\"recipient_card_id\":\"ca851674e1ca64e464896c4a11134b14636194936e64ab2299c6e0f726082290\",\"recipient_public_key\":\"MCowBQYDK2VwAyEA6Oidl/mpSnygd/l7K8pSgASBlSne13y/9Joig/4Opwg=\",\"recipient_long_term_card_id\":\"fe37aa673b1edd918413b9f0681e26c487580224535aa724c1ad6bc7c34d09ca\",\"recipient_long_term_public_key\":\"MCowBQYDK2VwAyEA9i+LE2E9rerarabuCYxLwt1KleMyfR46rEBBJV4rp54=\",\"recipient_one_time_card_id\":\"4037c39026054b1388a33727799b3627f6365601142c8a9594ed710ef3429f49\",\"recipient_one_time_public_key\":\"MCowBQYDK2VwAyEAqT2XPHY0IPOHzRgsGhDZTqbhIcfV/pb71wmMv8DUQk4=\",\"creation_date\":\"Oct 8, 2017 4:25:36 PM\",\"expiration_date\":\"Oct 9, 2017 4:25:36 PM\",\"session_id\":\"fIgW7LfCGZe8mHUhvAEBhL4vnHm99/q1k/jhWUR3hOs=\",\"additional_data\":null}");

		this.keyStorage = new JsonFileKeyStorage(System.getProperty("java.io.tmpdir"), prepareKeystorage(
				this.getClass().getClassLoader().getResourceAsStream("migration_1_1/alice.keyStorage")));

		SecureChatContext chatContext = new SecureChatContext(this.card, this.privateKey, crypto, ctx);
		chatContext.setDeviceManager(new DefaultDeviceManager());
		chatContext.setUserDataStorage(this.storage);
		chatContext.setKeyStorage(this.keyStorage);

		this.secureChat = new SecureChat(chatContext);
	}

	@Test
	public void checkVersion() throws MigrationException {
		assertEquals(Version.V1_0, this.secureChat.getPreviousVersion());
		assertEquals(Version.V1_1, SecureChat.Version.currentVersion);

		this.secureChat.initialize(false);

		assertEquals(Version.V1_0, this.secureChat.getPreviousVersion());

		this.secureChat.initialize(true);

		assertEquals(Version.V1_1, this.secureChat.getPreviousVersion());
	}

	@Test
	public void migration() throws CryptoException, MigrationException, SessionManagerException {
		KeyStorageManager keyStorageManager = new KeyStorageManager(this.crypto, this.keyStorage, this.card.getId());

		SessionInitializer sessionInitializer = new SessionInitializer(this.crypto, this.privateKey, this.card);
		SessionStorageManager sessionStorageManager = new SessionStorageManager(this.card.getId(), this.storage);
		SessionManager sessionManager = new SessionManager(this.card, this.privateKey, this.crypto, 1000,
				keyStorageManager, sessionStorageManager, sessionInitializer);

		MigrationV1_1 migration = new MigrationV1_1(this.crypto, this.privateKey, this.card, this.keyStorage,
				keyStorageManager, this.storage, sessionInitializer, sessionManager);
		migration.migrateKeyStorage();

		this.keyStorage.load(
				"VIRGIL.OWNER.e0a4db241866faf24494eb73fb739baee2e2a6fb209211e53e606866ab46abb1.EPH_KEY.ca851674e1ca64e464896c4a11134b14636194936e64ab2299c6e0f726082290");
		this.keyStorage.load(
				"VIRGIL.OWNER.e0a4db241866faf24494eb73fb739baee2e2a6fb209211e53e606866ab46abb1.EPH_KEY.bb81ef619008587d1caf03bdd2ea9cd087a4cfcd68d1956f6888b26b5ffa58e0");
		keyStorageManager.getOtPrivateKey("90bcb55efd70db515c502ed5c2cafebd77ce86a369b51351fc4b8f8db55ea915");
		keyStorageManager.getOtPrivateKey("6b454dbfe4ec5d7dfe08da9b5efb28e7da0269a690779e4cacaec3c32fabc1a7");

		migration.migrate();

		byte[] sessionId1 = ConvertionUtils.base64ToBytes("MTLQvU82MN8Fc/bKLkZDDRAfMTtBiOiQoTgMeGRl644=");
		sessionManager.loadSession("bb81ef619008587d1caf03bdd2ea9cd087a4cfcd68d1956f6888b26b5ffa58e0", sessionId1);

		byte[] sessionId2 = ConvertionUtils.base64ToBytes("fIgW7LfCGZe8mHUhvAEBhL4vnHm99/q1k/jhWUR3hOs=");
		sessionManager.loadSession("ca851674e1ca64e464896c4a11134b14636194936e64ab2299c6e0f726082290", sessionId2);

		try {
			this.keyStorage.load(
					"VIRGIL.OWNER.e0a4db241866faf24494eb73fb739baee2e2a6fb209211e53e606866ab46abb1.EPH_KEY.ca851674e1ca64e464896c4a11134b14636194936e64ab2299c6e0f726082290");
			fail();
		} catch (Exception e) {
		}
	}

	private String prepareKeystorage(InputStream is) {
		String fileName = UUID.randomUUID().toString();
		String dir = System.getProperty("java.io.tmpdir");

		try (OutputStream os = new FileOutputStream(new File(dir, fileName))) {
			try {
				StreamUtils.copyStream(is, os);
			} catch (IOException e) {
				fail(e.getMessage());
			} finally {
				is.close();
			}

		} catch (IOException e) {
			fail(e.getMessage());
		}

		return fileName;
	}

}
