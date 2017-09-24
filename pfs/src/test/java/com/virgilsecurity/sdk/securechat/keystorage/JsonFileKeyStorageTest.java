package com.virgilsecurity.sdk.securechat.keystorage;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.VirgilKeyEntry;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

public class JsonFileKeyStorageTest {

	private static final String CREATION_DATE_META_KEY = "created_at";

	private Crypto crypto;
	private JsonFileKeyStorage storage;

	private String alias;
	private KeyEntry entry;

	private KeyPair keyPair;

	private boolean failedConcurrency = false;

	@Before
	public void setUp() {
		crypto = new VirgilCrypto();
		storage = new JsonFileKeyStorage(System.getProperty("java.io.tmpdir"), UUID.randomUUID().toString());

		keyPair = crypto.generateKeys();

		alias = UUID.randomUUID().toString();

		entry = new VirgilKeyEntry();
		entry.setName(alias);
		entry.setValue(crypto.exportPrivateKey(keyPair.getPrivateKey()));
		entry.getMetadata().put(UUID.randomUUID().toString(), UUID.randomUUID().toString());
	}

	@Test
	public void exists_nullAlias() {
		assertFalse(storage.exists(null));
	}

	@Test
	public void exists_randomName() {
		assertFalse(storage.exists(UUID.randomUUID().toString()));
	}

	@Test
	public void exists() throws IOException {
		storage.store(entry);

		assertTrue(storage.exists(alias));
	}

	@Test
	public void store() {
		storage.store(entry);
		assertTrue(storage.exists(alias));
	}

	@Test(expected = KeyEntryAlreadyExistsException.class)
	public void store_duplicated() {
		storage.store(entry);
		storage.store(entry);
	}

	@Test
	public void load() {
		storage.store(entry);

		KeyEntry loadedEntry = storage.load(alias);

		assertThat(loadedEntry, instanceOf(VirgilKeyEntry.class));
		assertEquals(entry.getName(), loadedEntry.getName());
		assertArrayEquals(entry.getValue(), loadedEntry.getValue());
		assertEquals(entry.getMetadata(), loadedEntry.getMetadata());
		assertNotNull(entry.getMetadata().get(CREATION_DATE_META_KEY));
	}

	@Test(expected = KeyEntryNotFoundException.class)
	public void load_nullName() {
		storage.load(alias);
	}

	@Test(expected = KeyEntryNotFoundException.class)
	public void load_nonExisting() {
		storage.load(alias);
	}

	@Test
	public void delete() {
		storage.store(entry);
		storage.delete(alias);

		assertFalse(storage.exists(alias));
	}

	@Test(expected = KeyEntryNotFoundException.class)
	public void delete_nullName() {
		storage.delete((String) null);
	}

	@Test(expected = KeyEntryNotFoundException.class)
	public void delete_nonExisting() {
		storage.delete(alias);
	}

	@Test
	public void getAllKeysAttrs_empty() {
		List<KeyAttrs> keyAttrs = storage.getAllKeysAttrs();
		assertNotNull(keyAttrs);
		assertTrue(keyAttrs.isEmpty());
	}

	@Test
	public void getAllKeysAttrs() {
		storage.store(entry);
		List<KeyAttrs> keyAttrs = storage.getAllKeysAttrs();
		assertEquals(1, keyAttrs.size());

		KeyAttrs keyAttr = keyAttrs.get(0);
		assertNotNull(keyAttr);
		assertEquals(entry.getName(), keyAttr.getName());
		assertNotNull(keyAttr.getCreationDate());
	}

	@Test
	public void getAllKeysAttrs_predefinedCreationDate() {
		Calendar cal = Calendar.getInstance();
		Date date = cal.getTime();

		GsonBuilder builder = new GsonBuilder();
		Gson gson = builder.disableHtmlEscaping().setDateFormat("yyyy-MM-dd HH:mm:ss.SSS").create();

		entry.getMetadata().put(CREATION_DATE_META_KEY, gson.toJson(date));
		storage.store(entry);

		List<KeyAttrs> keyAttrs = storage.getAllKeysAttrs();
		assertEquals(1, keyAttrs.size());

		KeyAttrs keyAttr = keyAttrs.get(0);
		assertNotNull(keyAttr);
		assertEquals(entry.getName(), keyAttr.getName());
		assertNotNull(keyAttr.getCreationDate());
		assertEquals(date, keyAttr.getCreationDate());
	}

	@Test
	public void concurrentFlow() throws InterruptedException {
		failedConcurrency = false;
		ExecutorService exec = Executors.newFixedThreadPool(16);
		for (int i = 0; i < 10000; i++) {
			exec.execute(new Runnable() {
				@Override
				public void run() {
					String keyName = UUID.randomUUID().toString();

					try {
						assertFalse(storage.exists(keyName));

						KeyEntry keyEntry = new VirgilKeyEntry(keyName, ConvertionUtils.toBytes(keyName));
						storage.store(keyEntry);
						assertTrue(storage.exists(keyName));

						KeyEntry loadedEntry = storage.load(keyName);
						assertNotNull(loadedEntry);
						assertEquals(keyName, loadedEntry.getName());
						assertArrayEquals(keyEntry.getValue(), loadedEntry.getValue());

						storage.delete(keyName);
						assertFalse(storage.exists(keyName));
					} catch (Exception e) {
						failedConcurrency = true;
						throw e;
					}
				}
			});
		}
		exec.shutdown();
		exec.awaitTermination(5, TimeUnit.SECONDS);

		if (failedConcurrency) {
			fail();
		}
	}

}
