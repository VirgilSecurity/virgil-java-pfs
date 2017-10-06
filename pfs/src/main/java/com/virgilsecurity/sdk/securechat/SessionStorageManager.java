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

import java.lang.reflect.Type;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Logger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.virgilsecurity.sdk.securechat.model.SessionState;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

public class SessionStorageManager {

	private static final Logger log = Logger.getLogger(SessionStorageManager.class.getName());

	private String cardId;
	private UserDataStorage storage;

	private Gson gson;

	/**
	 * @param cardId
	 * @param storage
	 */
	public SessionStorageManager(String cardId, UserDataStorage storage) {
		this.cardId = cardId;
		this.storage = storage;
	}

	public void addSessionState(SessionState sessionState, String recipientCardId) {
		String sessionIdStr = ConvertionUtils.toBase64String(sessionState.getSessionId());
		log.fine(String.format("Adding session state for: %s, sessionId: %s", recipientCardId, sessionIdStr));

		synchronized (storage) {
			Map<String, Map<String, SessionState>> sessionStates = loadSessionStates(this.getSessionsEntryKey());
			Map<String, SessionState> recipientEntry = sessionStates.get(recipientCardId);
			if (recipientEntry == null) {
				recipientEntry = new HashMap<>();
				sessionStates.put(recipientCardId, recipientEntry);
			}
			recipientEntry.put(sessionIdStr, sessionState);

			this.storage.addData(this.cardId, this.getSessionsEntryKey(),
					getGson().toJson(sessionStates));
		}
	}

	public List<Entry<String, SessionState>> getAllSessionsStates() {
		log.fine("Getting all session's states");
		List<Entry<String, SessionState>> allSessionStates = new LinkedList<>();

		Map<String, Map<String, SessionState>> sessionStates = loadSessionStates(this.getSessionsEntryKey());
		for (Entry<String, Map<String, SessionState>> recipientStatesEntry : sessionStates.entrySet()) {
			String recipientCardId = recipientStatesEntry.getKey();
			for (SessionState sessionState : recipientStatesEntry.getValue().values()) {
				allSessionStates.add(new AbstractMap.SimpleEntry(recipientCardId, sessionState));
			}
		}
		return allSessionStates;
	}

	private Gson getGson() {
		if (this.gson == null) {
			GsonBuilder builder = new GsonBuilder();
			gson = builder.disableHtmlEscaping().setDateFormat("yyyy-MM-dd HH:mm:ss.SSS").create();
		}
		return gson;
	}

	public SessionState getNewestSessionState(String recipientCardId) {
		log.fine("Getting newest session state for: " + recipientCardId);

		SessionState newestState = null;
		for (Entry<String, SessionState> entry : loadRecipientSessions(recipientCardId).entrySet()) {
			SessionState state = entry.getValue();
			// TODO throw exception of session is corrupted
			if (newestState == null) {
				newestState = state;
			} else if (state.getCreationDate().after(newestState.getCreationDate())) {
				newestState = state;
			}
		}
		return newestState;
	}

	private String getSessionsEntryKey() {
		return String.format("VIRGIL.SESSIONSV2.OWNER=%s", this.cardId);
	}

	public SessionState getSessionState(String recipientCardId, byte[] sessionId) {
		String sessionIdStr = ConvertionUtils.toBase64String(sessionId);
		log.fine(String.format("Getting session state for: %s, sessionId: %s", recipientCardId, sessionIdStr));

		Map<String, SessionState> recipientSessions = loadRecipientSessions(recipientCardId);
		SessionState state = recipientSessions.get(sessionIdStr);

		return state;
	}

	public List<byte[]> getSessionStatesIds(String recipientCardId) {
		log.fine("Getting session states for: " + recipientCardId);
		List<byte[]> sessionIds = new ArrayList<>();
		Map<String, SessionState> recipientSessions = loadRecipientSessions(recipientCardId);

		for (SessionState sessionState : recipientSessions.values()) {
			sessionIds.add(sessionState.getSessionId());
		}

		return sessionIds;
	}

	private Map<String, SessionState> loadRecipientSessions(String recipientCardId) {
		Map<String, Map<String, SessionState>> sessionStates = loadSessionStates(this.getSessionsEntryKey());
		Map<String, SessionState> recipientStates = sessionStates.get(recipientCardId);
		if (recipientStates == null) {
			recipientStates = new HashMap<>();
		}
		return recipientStates;
	}

	private Map<String, Map<String, SessionState>> loadSessionStates(String sessionEntryKey) {
		String entry = storage.getData(this.cardId, this.getSessionsEntryKey());
		if (StringUtils.isBlank(entry)) {
			return new HashMap<>();
		}
		Type mapType = new TypeToken<Map<String, Map<String, SessionState>>>() {
		}.getType();
		Map<String, Map<String, SessionState>> sessionStates = getGson().fromJson(entry, mapType);

		return sessionStates;
	}

	public void removeSessionsStates(List<Entry<String, byte[]>> pairs) {
		if (pairs.isEmpty()) {
			return;
		}

		synchronized (storage) {
			Map<String, Map<String, SessionState>> sessionStates = loadSessionStates(this.getSessionsEntryKey());
			for (Entry<String, byte[]> pair : pairs) {
				Map<String, SessionState> recipientEntry = sessionStates.get(pair.getKey());
				if (recipientEntry == null) {
					// TODO throw exception if session not found
					continue;
				}
				recipientEntry.remove(ConvertionUtils.toBase64String(pair.getValue()));
			}

			this.storage.addData(this.cardId, this.getSessionsEntryKey(),
					getGson().toJson(sessionStates));
		}
	}

	public void removeSessionState(String recipientCardId, byte[] sessionId) {
		String sessionIdStr = ConvertionUtils.toBase64String(sessionId);
		log.fine(String.format("Removing session state for: %s, sessionId: %s", recipientCardId, sessionIdStr));

		synchronized (storage) {
			Map<String, Map<String, SessionState>> sessionStates = loadSessionStates(this.getSessionsEntryKey());
			Map<String, SessionState> recipientEntry = sessionStates.get(recipientCardId);
			if (recipientEntry == null) {
				// TODO throw exception if session not found
				return;
			}
			recipientEntry.remove(sessionIdStr);

			this.storage.addData(this.cardId, this.getSessionsEntryKey(),
					getGson().toJson(sessionStates));
		}
	}
}
