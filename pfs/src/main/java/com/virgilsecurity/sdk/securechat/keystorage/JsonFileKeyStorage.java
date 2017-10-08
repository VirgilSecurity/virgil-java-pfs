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
package com.virgilsecurity.sdk.securechat.keystorage;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.nio.file.InvalidPathException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.TypeAdapter;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyStorageException;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.VirgilKeyEntry;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * {@link KeyStorage} implementation which saves data to Json file.
 * 
 * @author Andrii Iakovenko
 *
 */
public class JsonFileKeyStorage implements KeyStorage {

	private static class ByteArrayToBase64TypeAdapter implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {
		public byte[] deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
				throws JsonParseException {
			return ConvertionUtils.base64ToBytes(json.getAsString());
		}

		public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
			return new JsonPrimitive(ConvertionUtils.toBase64String(src));
		}
	}

	private static class ClassTypeAdapter extends TypeAdapter<Class<?>> {
		@Override
		public Class<?> read(JsonReader jsonReader) throws IOException {
			if (jsonReader.peek() == JsonToken.NULL) {
				jsonReader.nextNull();
				return null;
			}
			Class<?> clazz = null;
			try {
				clazz = Class.forName(jsonReader.nextString());
			} catch (ClassNotFoundException exception) {
				throw new IOException(exception);
			}
			return clazz;
		}

		@Override
		public void write(JsonWriter jsonWriter, Class<?> clazz) throws IOException {
			if (clazz == null) {
				jsonWriter.nullValue();
				return;
			}
			jsonWriter.value(clazz.getName());
		}
	}
	private static class ClassTypeAdapterFactory implements TypeAdapterFactory {
		@SuppressWarnings("unchecked")
		@Override
		public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> typeToken) {
			if (!Class.class.isAssignableFrom(typeToken.getRawType())) {
				return null;
			}
			return (TypeAdapter<T>) new ClassTypeAdapter();
		}
	}
	private static class Entries extends HashMap<String, VirgilKeyEntry> {
		private static final long serialVersionUID = 261773342073013945L;

	}

	private static final String CREATION_DATE_META_KEY = "created_at";

	private String directoryName;

	private String fileName;

	private Gson gson;

	/**
	 * Create a new instance of {@code VirgilKeyStorage}
	 *
	 * ~/VirgilSecurity/KeyStore/virgil.keystore used by default.
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
	 * @param directoryName
	 *            The directory name which contains key storage file.
	 * @param fileName
	 *            The key storage file name.
	 */
	public JsonFileKeyStorage(String directoryName, String fileName) {
		this.directoryName = directoryName;
		this.fileName = fileName;

		init();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.virgilsecurity.sdk.securechat.keystorage.KeyStorage#delete(java.util.
	 * List)
	 */
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
	 * @see
	 * com.virgilsecurity.sdk.securechat.keystorage.KeyStorage#getAllKeysAttrs()
	 */
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
			this.gson = builder.registerTypeHierarchyAdapter(byte[].class, new ByteArrayToBase64TypeAdapter())
					.registerTypeAdapterFactory(new ClassTypeAdapterFactory()).disableHtmlEscaping()
					.setDateFormat("yyyy-MM-dd HH:mm:ss.SSS").create();
		}

		return gson;
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

	/**
	 * @param gson
	 *            the gson to set
	 */
	public void setGson(Gson gson) {
		this.gson = gson;
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.virgilsecurity.sdk.securechat.keystorage.KeyStorage#store(java.util.
	 * List)
	 */
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

}
