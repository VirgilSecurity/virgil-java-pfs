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
package com.virgilsecurity.sdk.securechat.utils;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.securechat.model.InitiationMessage;
import com.virgilsecurity.sdk.securechat.model.InitiatorSessionState;
import com.virgilsecurity.sdk.securechat.model.Message;
import com.virgilsecurity.sdk.securechat.model.Optional;
import com.virgilsecurity.sdk.securechat.model.ResponderSessionState;

/**
 * @author Andrii Iakovenko
 *
 */
public class SessionStateResolver {

	private static final Set<String> INITIATOR_SESSION_STATE_FIELDS;
	private static final Set<String> RESPONDER_SESSION_STATE_FIELDS;
	private static final Set<String> INITIALIZATION_MESSAGE_FIELDS;
	private static final Set<String> REGULAR_MESSAGE_FIELDS;

	static {
		INITIATOR_SESSION_STATE_FIELDS = Collections
				.unmodifiableSet(getSerializedNameValues(InitiatorSessionState.class));
		RESPONDER_SESSION_STATE_FIELDS = Collections
				.unmodifiableSet(getSerializedNameValues(ResponderSessionState.class));
		INITIALIZATION_MESSAGE_FIELDS = Collections.unmodifiableSet(getSerializedNameValues(InitiationMessage.class));
		REGULAR_MESSAGE_FIELDS = Collections.unmodifiableSet(getSerializedNameValues(Message.class));
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

	public static boolean isInitiationMessage(String json) {
		JsonElement jsonEl = new JsonParser().parse(json);
		if (!jsonEl.isJsonObject()) {
			return false;
		}
		JsonObject jsObj = (JsonObject) jsonEl;
		for (String fieldName : INITIALIZATION_MESSAGE_FIELDS) {
			if (!jsObj.has(fieldName)) {
				return false;
			}
		}
		return true;
	}

	public static boolean isRegularMessage(String json) {
		JsonElement jsonEl = new JsonParser().parse(json);
		if (!jsonEl.isJsonObject()) {
			return false;
		}
		JsonObject jsObj = (JsonObject) jsonEl;
		for (String fieldName : REGULAR_MESSAGE_FIELDS) {
			if (!jsObj.has(fieldName)) {
				return false;
			}
		}
		return true;
	}
}
