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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.securechat.impl.DefaultUserDataStorage;
import com.virgilsecurity.sdk.securechat.model.InitiatorSessionState;
import com.virgilsecurity.sdk.securechat.model.ResponderSessionState;
import com.virgilsecurity.sdk.securechat.model.SessionState;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChatSessionHelperTest {

    private static final String CARD_ID = UUID.randomUUID().toString();
    private UserDataStorage userDataStorage;

    @Before
    public void setUp() {
        userDataStorage = new DefaultUserDataStorage();
    }

    @Test
    public void saveSessionState() throws VirgilException {

        SecureChatSessionHelper helper = new SecureChatSessionHelper(CARD_ID, userDataStorage);
        assertTrue(helper.getAllSessions().isEmpty());

        String cardId = UUID.randomUUID().toString();
        SessionState sessionState = new InitiatorSessionState();
        helper.saveSessionState(sessionState, cardId);
        assertEquals(1, helper.getAllSessions().size());

        cardId = UUID.randomUUID().toString();
        sessionState = new ResponderSessionState();
        helper.saveSessionState(sessionState, cardId);
        assertEquals(2, helper.getAllSessions().size());
    }

    @Test
    public void removeSessionState() throws VirgilException {
        SecureChatSessionHelper helper = new SecureChatSessionHelper(CARD_ID, userDataStorage);
        assertTrue(helper.getAllSessions().isEmpty());

        String cardId = UUID.randomUUID().toString();
        SessionState sessionState = new InitiatorSessionState();
        helper.saveSessionState(sessionState, cardId);
        assertEquals(1, helper.getAllSessions().size());

        helper.removeSessionState(cardId);

        assertTrue(helper.getAllSessions().isEmpty());
    }

    @Test
    @Ignore
    public void removeOldSessions() {
    }

    @Test
    @Ignore
    public void getSessionState() {

    }

    @Test
    public void getCardId_null() {
        assertNull(SecureChatSessionHelper.getCardId(null));
    }

    @Test
    public void getCardId_empty() {
        assertNull(SecureChatSessionHelper.getCardId(""));
    }

    @Test
    public void getCardId_wrongPattern() {
        assertNull(SecureChatSessionHelper.getCardId(CARD_ID));
    }

    @Test
    public void getCardId() {
        String cardId = UUID.randomUUID().toString();
        assertEquals(cardId, SecureChatSessionHelper.getCardId("VIRGIL.SESSION." + cardId));
        assertEquals(CARD_ID, SecureChatSessionHelper.getCardId(SecureChatSessionHelper.getSessionName(CARD_ID)));
    }

    @Test
    @Ignore
    public void getEphKeys() {
    }

    @Test
    @Ignore
    public void getLtCards() {
    }

    @Test
    @Ignore
    public void getOtCards() {
    }

    @Test
    public void getSessionName() {
        assertEquals("VIRGIL.SESSION." + CARD_ID, SecureChatSessionHelper.getSessionName(CARD_ID));
    }

    @Test
    public void getSessionName_nullCardId() {
        assertEquals("VIRGIL.SESSION.null", SecureChatSessionHelper.getSessionName(null));
    }

    @Test
    public void isSessionName() {
        assertTrue(SecureChatSessionHelper.isSessionName("VIRGIL.SESSION." + CARD_ID));
        assertTrue(SecureChatSessionHelper.isSessionName("VIRGIL.SESSION.null"));
        assertFalse(SecureChatSessionHelper.isSessionName("VIRGIL.SESSION."));
    }

    @Test
    public void isSessionName_nullName() {
        assertFalse(SecureChatSessionHelper.isSessionName(null));
    }

    @Test
    public void getSuiteName() {
        SecureChatSessionHelper helper = new SecureChatSessionHelper(CARD_ID, userDataStorage);
        assertEquals("VIRGIL.DEFAULTS." + CARD_ID, helper.getSuiteName());
    }

    @Test(expected = NullArgumentException.class)
    public void isSessionStateExpired_nullDate() {
        SecureChatSessionHelper.isSessionStateExpired(null, new SessionState());
    }

    @Test(expected = NullArgumentException.class)
    public void isSessionStateExpired_nullSessionState() {
        SecureChatSessionHelper.isSessionStateExpired(new Date(), null);
    }

    @Test
    public void isSessionStateExpired() {
        SessionState sessionState = new SessionState();

        Calendar cal = Calendar.getInstance();
        Date date = cal.getTime();

        sessionState.setExpirationDate(cal.getTime());
        assertFalse("The same time", SecureChatSessionHelper.isSessionStateExpired(date, sessionState));

        cal.add(Calendar.SECOND, 1);
        sessionState.setExpirationDate(cal.getTime());
        assertFalse("Expire in a future", SecureChatSessionHelper.isSessionStateExpired(date, sessionState));

        cal.add(Calendar.SECOND, -2);
        sessionState.setExpirationDate(cal.getTime());
        assertTrue("Expired", SecureChatSessionHelper.isSessionStateExpired(date, sessionState));
    }
}
