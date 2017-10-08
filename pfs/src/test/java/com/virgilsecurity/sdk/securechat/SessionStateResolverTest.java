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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.virgilsecurity.sdk.securechat.model.InitiationMessage;
import com.virgilsecurity.sdk.securechat.model.InitiatorSessionState;
import com.virgilsecurity.sdk.securechat.model.ResponderSessionState;
import com.virgilsecurity.sdk.securechat.utils.GsonUtils;
import com.virgilsecurity.sdk.securechat.utils.SessionStateResolver;

/**
 * @author Andrii Iakovenko
 *
 */
public class SessionStateResolverTest {

	@Test
	public void isInitiatorSessionState_nullFields() {
		InitiatorSessionState state = new InitiatorSessionState();

		String json = GsonUtils.getGson().toJson(state);
		assertTrue(SessionStateResolver.isInitiatorSessionState(json));
	}

	@Test
	public void isInitiatorSessionState_false() {
		ResponderSessionState state = new ResponderSessionState();

		String json = GsonUtils.getGson().toJson(state);
		assertFalse(SessionStateResolver.isInitiatorSessionState(json));
	}

	@Test
	public void isResponderSessionState_nullFields() {
		ResponderSessionState state = new ResponderSessionState();

		String json = GsonUtils.getGson().toJson(state);
		assertTrue(SessionStateResolver.isResponderSessionState(json));
	}

	@Test
	public void isResponderSessionState_false() {
		InitiatorSessionState state = new InitiatorSessionState();

		String json = GsonUtils.getGson().toJson(state);
		assertFalse(SessionStateResolver.isResponderSessionState(json));
	}

	@Test
	public void isInitiationMessage() {
		InitiationMessage message = new InitiationMessage(TestUtils.generateCardId(), TestUtils.generateCardId(),
				TestUtils.generateCardId(), TestUtils.generateCardId(), TestUtils.generateBytes(100),
				TestUtils.generateBytes(20), TestUtils.generateBytes(16), TestUtils.generateBytes(100));

		String json = GsonUtils.getGson().toJson(message);
		assertTrue(SessionStateResolver.isInitiationMessage(json));
	}

	@Test
	public void isInitiationMessage_nullOtc() {
		String json = "{\"initiator_ic_id\":\"630d64d6-975b-4782-ba27-fde70296d3be\",\"responder_ic_id\":\"8424e6b1-e541-4822-b279-ac27a0a0ecc9\",\"responder_ltc_id\":\"10aaebf1-da25-4491-81f9-80a02d5345ad\",\"eph\":\"JXU/E3qfaB2qFlMFoTgRBiCa9PDRelsE475wwQl03BEwALYW6Y2EY20+fe6HlOBjYO+Pv9q3VS9AEdCYjnn4jMiCtQFJggq6r9JDXp+k1402I3OPRbFF/Kny9FdIf8jGCoj70g==\",\"sign\":\"s8YTVjDRcjSZUD5WNkoA5JdPRgg=\",\"salt\":\"kJYE/udJfHQfM29jpZ5/GQ==\",\"ciphertext\":\"o9tsBMX96ogJTbnV7LqLJYr65hI+Er94oKjSAMORlYqJbhnoFbL3a99c1TtyWDCMtwFMhQ31rMsBp1d8uO406zOpjSFblXXJjcfGMt023W15pHbhZb6jvssjvw0ZjEip970cgw==\"}";
		assertTrue(SessionStateResolver.isInitiationMessage(json));
	}

}
