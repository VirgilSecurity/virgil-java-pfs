package com.virgilsecurity.sdk.securechat.keystorage;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.nio.file.InvalidPathException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyStorageException;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.VirgilKeyEntry;
import com.virgilsecurity.sdk.utils.StringUtils;

public class JsonFileKeyStorage implements KeyStorage {

	private static final String CREATION_DATE_META_KEY = "created_at";

	private String directoryName;
	private String fileName;
	private Gson gson;

	/**
	 * Create a new instance of {@code VirgilKeyStorage}
	 *
	 */
	public JsonFileKeyStorage() {
		StringBuilder path = new StringBuilder(System.getProperty("user.home"));
		path.append(File.separator).append("VirgilSecurity");
		path.append(File.separator).append("KeyStore");

		this.directoryName = path.toString();
		this.fileName = "virgil.keystore";

		init();
	}

	/**
	 * Create a new instance of {@code VirgilKeyStorage}
	 *
	 */
	public JsonFileKeyStorage(String directoryName, String fileName) {
		this.directoryName = directoryName;
		this.fileName = fileName;

		init();
	}

	private void init() {
		File dir = new File(this.directoryName);

		if (dir.exists()) {
			if (!dir.isDirectory()) {
				throw new InvalidPathException(this.directoryName, "Is not a directory");
			}
		} else {
			dir.mkdirs();
		}
		File file = new File(dir, this.fileName);
		if (!file.exists()) {
			save(new Entries());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.virgilsecurity.sdk.crypto.KeyStore#store(com.virgilsecurity.sdk.
	 * crypto.KeyEntry)
	 */
	@Override
	public void store(KeyEntry keyEntry) {
		String name = keyEntry.getName();
		String creationDateStr = getGson().toJson(new Date());

		synchronized (this) {
			Entries entries = load();
			if (entries.containsKey(name)) {
				throw new KeyEntryAlreadyExistsException();
			}
			if (!keyEntry.getMetadata().containsKey(CREATION_DATE_META_KEY)) {
				keyEntry.getMetadata().put(CREATION_DATE_META_KEY, creationDateStr);
			}
			entries.put(name, (VirgilKeyEntry) keyEntry);
			save(entries);
		}
	}

	@Override
	public void store(List<KeyEntry> keyEntries) {
		synchronized (this) {
			Entries entries = load();
			for (KeyEntry keyEntry : keyEntries) {
				entries.put(keyEntry.getName(), (VirgilKeyEntry) keyEntry);
			}
			save(entries);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.virgilsecurity.sdk.crypto.KeyStore#load(java.lang.String)
	 */
	@Override
	public KeyEntry load(String keyName) {
		synchronized (this) {
			Entries entries = load();
			if (!entries.containsKey(keyName)) {
				throw new KeyEntryNotFoundException();
			}
			VirgilKeyEntry entry = entries.get(keyName);
			entry.setName(keyName);
			return entry;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.virgilsecurity.sdk.crypto.KeyStore#exists(java.lang.String)
	 */
	@Override
	public boolean exists(String keyName) {
		if (keyName == null) {
			return false;
		}
		synchronized (this) {
			Entries entries = load();
			return entries.containsKey(keyName);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.virgilsecurity.sdk.crypto.KeyStore#delete(java.lang.String)
	 */
	@Override
	public void delete(String keyName) {
		synchronized (this) {
			Entries entries = load();
			if (!entries.containsKey(keyName)) {
				throw new KeyEntryNotFoundException();
			}
			entries.remove(keyName);
			save(entries);
		}
	}

	@Override
	public void delete(List<String> keyNames) {
		synchronized (this) {
			Entries entries = load();
			for (String keyName : keyNames) {
				entries.remove(keyName);
			}
			save(entries);
		}
	}

	private Entries load() {
		File file = new File(this.directoryName, this.fileName);
		try (FileInputStream is = new FileInputStream(file)) {
			ByteArrayOutputStream os = new ByteArrayOutputStream();

			byte[] buffer = new byte[4096];
			int n = 0;
			while (-1 != (n = is.read(buffer))) {
				os.write(buffer, 0, n);
			}

			byte[] bytes = os.toByteArray();

			Entries entries = getGson().fromJson(new String(bytes, Charset.forName("UTF-8")), Entries.class);

			return entries;
		} catch (Exception e) {
			throw new KeyStorageException(e);
		}
	}

	/**
	 * @param entries
	 */
	private void save(Entries entries) {
		File file = new File(this.directoryName, this.fileName);
		try (FileOutputStream os = new FileOutputStream(file)) {
			String json = getGson().toJson(entries);
			os.write(json.getBytes(Charset.forName("UTF-8")));
		} catch (Exception e) {
			throw new KeyStorageException(e);
		}
	}

	@Override
	public List<KeyAttrs> getAllKeysAttrs() {
		Entries entries = null;
		synchronized (this) {
			entries = load();
		}
		List<KeyAttrs> keyAttrs = new ArrayList<>(entries.size());
		for (Entry<String, VirgilKeyEntry> entrySet : entries.entrySet()) {
			String name = entrySet.getKey();
			Date creationDate = null;
			if (entrySet.getValue().getMetadata() != null) {
				String creationDateStr = entrySet.getValue().getMetadata().get(CREATION_DATE_META_KEY);
				if (!StringUtils.isBlank(creationDateStr)) {
					creationDate = getGson().fromJson(creationDateStr, Date.class);
				}
			}
			if (creationDate == null) {
				creationDate = new Date();
			}
			keyAttrs.add(new KeyAttrs(name, creationDate));
		}
		return keyAttrs;
	}

	private Gson getGson() {
		if (this.gson == null) {
			GsonBuilder builder = new GsonBuilder();
			this.gson = builder.disableHtmlEscaping().setDateFormat("yyyy-MM-dd HH:mm:ss.SSS").create();
		}

		return gson;
	}

	private static class Entries extends HashMap<String, VirgilKeyEntry> {
		private static final long serialVersionUID = 261773342073013945L;

	}

}
