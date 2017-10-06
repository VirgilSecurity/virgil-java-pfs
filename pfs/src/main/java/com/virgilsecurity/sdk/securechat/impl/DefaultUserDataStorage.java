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
package com.virgilsecurity.sdk.securechat.impl;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.virgilsecurity.sdk.securechat.UserDataStorage;

/**
 * The in-memory implementation of user data storage.
 * 
 * @author Andrii Iakovenko
 *
 */
public class DefaultUserDataStorage implements UserDataStorage {

	private Map<String, Map<String, String>> defaults;

	/**
	 * Create new instance of {@link DefaultUserDataStorage}.
	 */
	public DefaultUserDataStorage() {
		defaults = Collections.synchronizedMap(new HashMap<String, Map<String, String>>());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.virgilsecurity.sdk.securechat.UserDataStorage#addData(java.lang.
	 * String, java.lang.String, java.lang.String)
	 */
	@Override
	public void addData(String storageName, String key, String value) {
		getAllData(storageName).put(key, value);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.virgilsecurity.sdk.securechat.UserDataStorage#getAllData(java.lang.
	 * String)
	 */
	@Override
	public Map<String, String> getAllData(String storageName) {
		if (defaults.containsKey(storageName)) {
			Map<String, String> data = defaults.get(storageName);
			return data;
		}
		Map<String, String> data = Collections.synchronizedMap(new HashMap<String, String>());
		defaults.put(storageName, data);
		return data;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.virgilsecurity.sdk.securechat.UserDataStorage#getData(java.lang.
	 * String, java.lang.String)
	 */
	@Override
	public String getData(String storageName, String key) {
		return getAllData(storageName).get(key);
	}

	@Override
	public void removeAll(String storageName) {
		defaults.remove(storageName);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.virgilsecurity.sdk.securechat.UserDataStorage#removeData(java.lang.
	 * String, java.lang.String)
	 */
	@Override
	public void removeData(String storageName, String key) {
		getAllData(storageName).remove(key);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.virgilsecurity.sdk.securechat.UserDataStorage#synchronize()
	 */
	@Override
	public void synchronize() {
		// TODO Auto-generated method stub
	}

}
