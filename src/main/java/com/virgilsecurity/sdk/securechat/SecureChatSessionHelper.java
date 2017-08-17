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

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.securechat.exceptions.CorruptedSavedSessionException;
import com.virgilsecurity.sdk.securechat.model.InitiatorSessionState;
import com.virgilsecurity.sdk.securechat.model.ResponderSessionState;
import com.virgilsecurity.sdk.securechat.model.SessionState;
import com.virgilsecurity.sdk.securechat.utils.GsonUtils;
import com.virgilsecurity.sdk.securechat.utils.SessionStateResolver;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChatSessionHelper {

    private static final String DEFAULT_SUITE_NAME = "VIRGIL.DEFAULTS.%s";
    private static final String DEFAULT_SESSION_NAME = "VIRGIL.SESSION.%s";
    private static final String DEFAULT_SESSION_NAME_SEARCH_PATTERN = "VIRGIL.SESSION.";

    private String cardId;
    private UserDataStorage userDefaults;

    /**
     * Create new instance of {@link SecureChatSessionHelper}.
     * 
     * @param cardId
     * @param dataStorage
     */
    public SecureChatSessionHelper(String cardId, UserDataStorage dataStorage) {
        this.userDefaults = dataStorage;
        this.cardId = cardId;
    }

    public static String getSessionName(String cardId) {
        return String.format(DEFAULT_SESSION_NAME, cardId);
    }

    public static boolean isSessionName(String name) {
        return name != null && name.length() > DEFAULT_SESSION_NAME_SEARCH_PATTERN.length()
                && name.startsWith(DEFAULT_SESSION_NAME_SEARCH_PATTERN);
    }

    public String getSuiteName() {
        return String.format(DEFAULT_SUITE_NAME, this.cardId);
    }

    public static boolean isSessionStateExpired(Date date, SessionState session) {
        if (date == null) {
            throw new NullArgumentException("date");
        }
        if (session == null) {
            throw new NullArgumentException("session");
        }
        return date.after(session.getExpirationDate());
    }

    public void saveSessionState(SessionState sessionState, String cardId) {
        String json = GsonUtils.getGson().toJson(sessionState);
        userDefaults.addData(this.getSuiteName(), getSessionName(cardId), json);
    }

    public void removeSessionState(String cardId) {
        removeSessionState(cardId, true);
    }

    private void removeSessionState(String cardId, boolean synchronize) {
        removeSessionStateByName(getSessionName(cardId), synchronize);
    }

    private void removeSessionStateByName(String sessionName, boolean synchronize) {
        userDefaults.removeData(this.getSuiteName(), sessionName);
        if (synchronize) {
            userDefaults.synchronize();
        }
    }

    public void removeSessionsStates(Collection<String> recipientCardIds) {
        List<String> names = new LinkedList<>();
        for (String cardId : recipientCardIds) {
            names.add(getSessionName(cardId));
        }
        removeSessionsStatesByNames(names);
    }

    public void removeSessionsStatesByNames(Collection<String> names) {
        for (String sessionName : names) {
            this.removeSessionStateByName(sessionName, false);
        }
        userDefaults.synchronize();
    }

    public void removeOldSessions() throws VirgilException {
        Map<String, SessionState> allSessions;
        try {
            allSessions = this.getAllSessions();
        } catch (CorruptedSavedSessionException e) {
            throw new VirgilException(e);
        }

        Date date = new Date();
        for (Entry<String, SessionState> entry : allSessions.entrySet()) {
            if (isSessionStateExpired(date, entry.getValue())) {
                allSessions.remove(entry.getKey());
            }
        }
    }

    public SessionState getSessionState(String cardId) throws CorruptedSavedSessionException {
        String json = userDefaults.getData(this.getSuiteName(), getSessionName(cardId));

        if (json == null) {
            return null;
        }

        SessionState state = null;
        if (SessionStateResolver.isInitiatorSessionState(json)) {
            state = GsonUtils.getGson().fromJson(json, InitiatorSessionState.class);
        } else if (SessionStateResolver.isResponderSessionState(json)) {
            state = GsonUtils.getGson().fromJson(json, ResponderSessionState.class);
        } else {
            throw new CorruptedSavedSessionException();
        }

        return state;
    }

    public Map<String, SessionState> getAllSessions() throws CorruptedSavedSessionException {
        Map<String, String> defaults = userDefaults.getAllData(this.getSuiteName());
        return getAllSessions(defaults);
    }

    private Map<String, SessionState> getAllSessions(Map<String, String> defaults)
            throws CorruptedSavedSessionException {
        Map<String, SessionState> result = new HashMap<>();
        for (Entry<String, String> entry : defaults.entrySet()) {
            if (!isSessionName(entry.getKey())) {
                continue;
            }

            String json = entry.getValue();
            SessionState sessionState;
            if (SessionStateResolver.isInitiatorSessionState(json)) {
                sessionState = GsonUtils.getGson().fromJson(json, InitiatorSessionState.class);
            } else if (SessionStateResolver.isResponderSessionState(json)) {
                sessionState = GsonUtils.getGson().fromJson(json, ResponderSessionState.class);
            } else {
                throw new CorruptedSavedSessionException();
            }
            result.put(entry.getKey(), sessionState);
        }
        return result;
    }

    public static String getCardId(String sessionName) {
        if (sessionName == null) {
            return null;
        }
        if (!sessionName.startsWith(DEFAULT_SESSION_NAME_SEARCH_PATTERN)) {
            return null;
        }

        String cardId = sessionName.replaceFirst(DEFAULT_SESSION_NAME_SEARCH_PATTERN, "");
        return cardId;
    }

    public Set<String> getEphKeys() throws VirgilException {
        Set<String> result = new HashSet<>();

        Map<String, SessionState> allSessions = this.getAllSessions();
        for (SessionState sessionState : allSessions.values()) {
            if (sessionState instanceof InitiatorSessionState) {
                result.add(((InitiatorSessionState) sessionState).getEphKeyName());
            }
        }

        return result;
    }

    public Set<String> getLtCards() throws VirgilException {
        Set<String> result = new HashSet<>();

        Map<String, SessionState> allSessions = this.getAllSessions();
        for (SessionState sessionState : allSessions.values()) {
            if (sessionState instanceof ResponderSessionState) {
                result.add(((ResponderSessionState) sessionState).getRecipientLongTermCardId());
            }
        }

        return result;
    }

    public Set<String> getOtCards() throws VirgilException {
        Set<String> result = new HashSet<>();

        Map<String, SessionState> allSessions = this.getAllSessions();
        for (SessionState sessionState : allSessions.values()) {
            if (sessionState instanceof ResponderSessionState) {
                ResponderSessionState responderSessionState = (ResponderSessionState) sessionState;
                if (!StringUtils.isBlank(responderSessionState.getRecipientOneTimeCardId())) {
                    result.add(responderSessionState.getRecipientOneTimeCardId());
                }
            }
        }

        return result;
    }

}
