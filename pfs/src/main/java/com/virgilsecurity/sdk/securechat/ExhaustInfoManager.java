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

import java.util.logging.Logger;

import com.virgilsecurity.sdk.securechat.model.ExhaustInfo;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

public class ExhaustInfoManager {

	private static final Logger log = Logger.getLogger(ExhaustInfoManager.class.getName());

	private String cardId;
	private UserDataStorage storage;

	/**
	 * Create new instance of ExhaustInfoManager.
	 * 
	 * @param cardId
	 *            the Virgil Card identifier.
	 * @param storage
	 *            the user data storage.
	 */
	public ExhaustInfoManager(String cardId, UserDataStorage storage) {
		super();
		this.cardId = cardId;
		this.storage = storage;
	}

	private String getExhaustEntryKey() {
		return String.format("VIRGIL.EXHAUSTINFO.OWNER=%s", this.cardId);
	}

	/**
	 * Load exhaust info from storage.
	 * 
	 * @return the exhaust info.
	 */
	public ExhaustInfo getKeysExhaustInfo() {
		log.fine("Getting exhaust info");

		String entry = storage.getData(this.cardId, this.getExhaustEntryKey());
		if (StringUtils.isBlank(entry)) {
			return new ExhaustInfo();
		}
		ExhaustInfo info = ConvertionUtils.getGson().fromJson(entry, ExhaustInfo.class);

		return info;
	}

	/**
	 * Save exhaust info in storage.
	 * 
	 * @param keysExhaustInfo
	 */
	public void saveKeysExhaustInfo(ExhaustInfo keysExhaustInfo) {
		log.fine("Saving exhaust info");

		this.storage.addData(this.cardId, this.getExhaustEntryKey(), ConvertionUtils.getGson().toJson(keysExhaustInfo));
	}
}
