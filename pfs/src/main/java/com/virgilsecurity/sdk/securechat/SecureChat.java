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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.virgilsecurity.sdk.client.exceptions.CardValidationException;
import com.virgilsecurity.sdk.client.exceptions.VirgilClientException;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.pfs.EphemeralCardValidator;
import com.virgilsecurity.sdk.pfs.VirgilPFSClient;
import com.virgilsecurity.sdk.pfs.model.RecipientCardsSet;
import com.virgilsecurity.sdk.pfs.model.response.OtcCountResponse;
import com.virgilsecurity.sdk.securechat.exceptions.CorruptedSavedSessionException;
import com.virgilsecurity.sdk.securechat.exceptions.RemoveSessionException;
import com.virgilsecurity.sdk.securechat.exceptions.SessionCheckException;
import com.virgilsecurity.sdk.securechat.exceptions.StartNewSessionException;
import com.virgilsecurity.sdk.securechat.model.InitiationMessage;
import com.virgilsecurity.sdk.securechat.model.InitiatorSessionState;
import com.virgilsecurity.sdk.securechat.model.Message;
import com.virgilsecurity.sdk.securechat.model.MessageType;
import com.virgilsecurity.sdk.securechat.model.ResponderSessionState;
import com.virgilsecurity.sdk.securechat.model.SessionState;
import com.virgilsecurity.sdk.securechat.utils.SessionStateResolver;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChat {

    private static final Logger LOGGER = Logger.getLogger(SecureChat.class.getName());

    private SecureChatContext config;
    private VirgilPFSClient client;

    SecureChatKeyHelper keyHelper;
    SecureChatCardsHelper cardsHelper;
    SecureChatSessionHelper sessionHelper;

    /**
     * Create new instance of {@link SecureChat}.
     * 
     * @param config
     *            the secure chat context.
     */
    public SecureChat(SecureChatContext config) {
        this.config = config;
        this.client = new VirgilPFSClient(config.getContext());
        this.keyHelper = new SecureChatKeyHelper(config.getCrypto(), config.getKeyStorage(),
                config.getIdentityCard().getId(), config.getLongTermKeysTtl());
        this.cardsHelper = new SecureChatCardsHelper(config.getCrypto(), config.getPrivateKey(), this.client,
                this.config.getDeviceManager(), this.keyHelper);
        this.sessionHelper = new SecureChatSessionHelper(config.getIdentityCard().getId(), config.getUserDefaults());
    }

    private SecureSession startNewSession(CardModel recipientCard, RecipientCardsSet cardsSet, byte[] additionalData)
            throws CardValidationException {
        String identityCardId = recipientCard.getId();
        byte[] identityPublicKeyData = recipientCard.getSnapshotModel().getPublicKeyData();
        byte[] longTermPublicKeyData = cardsSet.getLongTermCard().getSnapshotModel().getPublicKeyData();

        KeyPair ephKeyPair = this.config.getCrypto().generateKeys();
        PrivateKey ephPrivateKey = ephKeyPair.getPrivateKey();

        String ephKeyName = this.keyHelper.persistEphPrivateKey(ephPrivateKey, identityCardId);

        EphemeralCardValidator validator = new EphemeralCardValidator(this.config.getCrypto());
        validator.addVerifier(identityCardId, identityPublicKeyData);

        if (!validator.validate(cardsSet.getLongTermCard())) {
            throw new CardValidationException(Constants.Errors.LTC_VALIDATION_FAILED,
                    "Responder LongTerm card validation failed.");
        }

        if (cardsSet.getOneTimeCard() != null) {
            if (!validator.validate(cardsSet.getOneTimeCard())) {
                throw new CardValidationException(Constants.Errors.OTC_VALIDATION_FAILED,
                        "Responder OneTime card validation failed.");
            }
        }

        SecureSession.CardEntry identityCardEntry = new SecureSession.CardEntry(identityCardId, identityPublicKeyData);
        SecureSession.CardEntry ltCardEntry = new SecureSession.CardEntry(cardsSet.getLongTermCard().getId(),
                longTermPublicKeyData);

        SecureSession.CardEntry otCardEntry = null;
        if (cardsSet.getOneTimeCard() != null) {
            byte[] oneTimePublicKeyData = cardsSet.getOneTimeCard().getSnapshotModel().getPublicKeyData();
            otCardEntry = new SecureSession.CardEntry(cardsSet.getOneTimeCard().getId(), oneTimePublicKeyData);
        }

        Date date = new Date();
        SecureSessionInitiator secureSession = new SecureSessionInitiator(this.config, this.sessionHelper,
                additionalData, this.config.getIdentityCard(), ephPrivateKey, ephKeyName, identityCardEntry,
                ltCardEntry, otCardEntry, false, date, this.getSessionExpirationDate(date));

        return secureSession;
    }

    public SecureSession startNewSession(CardModel card, byte[] additionalData) throws VirgilException {
        // Check for existing session state
        SessionState sessionState = null;
        try {
            sessionState = this.sessionHelper.getSessionState(card.getId());
        } catch (CorruptedSavedSessionException e) {
            throw e;
        } catch (Exception e) {
            throw new SessionCheckException("Error checking for existing session.", e);
        }
        // If we have existing session
        if (sessionState != null) {
            // If session is not expired - return error
            if (!this.isSessionStateExpired(new Date(), sessionState)) {
                throw new StartNewSessionException(Constants.Errors.ACTIVE_SESSION_EXISTS,
                        "Found active session for given recipient. Try to loadUpSession.");
            }
            // If session is expired, just remove old session and create new one
            this.removeSession(card.getId());
        }

        // Get recipient's credentials
        List<RecipientCardsSet> cardsSets = this.client.getRecipientCardsSet(Arrays.asList(card.getId()));
        if (cardsSets.isEmpty()) {
            throw new VirgilClientException("Error obtaining recipient cards set. Empty set.");
        }

        RecipientCardsSet cardsSet = cardsSets.get(0);
        return this.startNewSession(card, cardsSet, additionalData);
    }

    public SecureSession activeSession(String recipientCardId) throws VirgilClientException, CryptoException {
        SessionState sessionState = this.sessionHelper.getSessionState(recipientCardId);
        if (sessionState == null) {
            return null;
        }
        if (this.isSessionStateExpired(new Date(), sessionState)) {
            try {
                this.removeSession(recipientCardId);
            } catch (VirgilClientException e) {
                LOGGER.log(Level.WARNING, "Error occured while removing expired session in activeSession", e);
            }
            return null;
        }

        SecureSession secureSession = null;
        try {
            secureSession = this.recoverSession(this.config.getIdentityCard(), sessionState);
        } catch (Exception e) {
            // TODO
        }

        return secureSession;
    }

    public synchronized void gentleReset() throws CorruptedSavedSessionException, RemoveSessionException {
        Map<String, SessionState> sessionStates = this.sessionHelper.getAllSessions();

        for (Entry<String, SessionState> sessionState : sessionStates.entrySet()) {
            String cardId = SecureChatSessionHelper.getCardId(sessionState.getKey());
            if (cardId != null) {
                this.removeSession(cardId);
            }
        }
        this.removeAllKeys();
    }

    private void removeAllKeys() {
        this.keyHelper.gentleReset();
    }

    private boolean isSessionStateExpired(Date date, SessionState sessionState) {
        return (date.after(sessionState.getExpirationDate()));
    }

    private SecureSession recoverSession(CardModel myIdentityCard, SessionState sessionState)
            throws VirgilClientException, CryptoException {
        if (sessionState instanceof InitiatorSessionState) {
            return this.recoverInitiatorSession(myIdentityCard, (InitiatorSessionState) sessionState);
        } else if (sessionState instanceof ResponderSessionState) {
            return this.recoverResponderSession(myIdentityCard, (ResponderSessionState) sessionState);
        } else {
            throw new VirgilClientException("Unknown session state.");
        }
    }

    private SecureSession recoverInitiatorSession(CardModel myIdentityCard, InitiatorSessionState initiatorSessionState)
            throws VirgilClientException {
        String ephKeyName = initiatorSessionState.getEphKeyName();
        PrivateKey ephPrivateKey = null;
        try {
            ephPrivateKey = this.keyHelper.getEphPrivateKeyByEntryName(ephKeyName);
        } catch (Exception e) {
            throw new VirgilClientException("Error getting ephemeral key from storage.");
        }

        SecureSession.CardEntry identityCardEntry = new SecureSession.CardEntry(
                initiatorSessionState.getRecipientCardId(), initiatorSessionState.getRecipientPublicKey());
        SecureSession.CardEntry ltCardEntry = new SecureSession.CardEntry(
                initiatorSessionState.getRecipientLongTermCardId(),
                initiatorSessionState.getRecipientLongTermPublicKey());
        SecureSession.CardEntry otCardEntry = null;
        String recOtId = initiatorSessionState.getRecipientOneTimeCardId();
        byte[] recOtPub = initiatorSessionState.getRecipientOneTimePublicKey();

        if ((!StringUtils.isBlank(recOtId)) && (recOtPub != null) && (recOtPub.length > 0)) {
            otCardEntry = new SecureSession.CardEntry(recOtId, recOtPub);
        }

        byte[] additionalData = initiatorSessionState.getAdditionalData();

        SecureSession secureSession = new SecureSessionInitiator(this.config, this.sessionHelper, additionalData,
                myIdentityCard, ephPrivateKey, ephKeyName, identityCardEntry, ltCardEntry, otCardEntry, true,
                initiatorSessionState.getCreationDate(), initiatorSessionState.getExpirationDate());

        return secureSession;
    }

    private SecureSession recoverResponderSession(CardModel myIdentityCard, ResponderSessionState responderSessionState)
            throws CryptoException {
        SecureSession.CardEntry initiatorCardEntry = new SecureSession.CardEntry(
                responderSessionState.getRecipientIdentityCardId(),
                responderSessionState.getRecipientIdentityPublicKey());
        byte[] additionalData = responderSessionState.getAdditionalData();

        SecureSessionResponder secureSession = new SecureSessionResponder(this.config, this.sessionHelper,
                additionalData, this.keyHelper, initiatorCardEntry, responderSessionState.getEphPublicKeyData(),
                responderSessionState.getRecipientLongTermCardId(), responderSessionState.getRecipientOneTimeCardId(),
                responderSessionState.getCreationDate(), responderSessionState.getExpirationDate());

        return secureSession;
    }

    public SecureSession loadUpSession(CardModel card, String message) throws VirgilException {
        return loadUpSession(card, message, null);
    }

    public SecureSession loadUpSession(CardModel card, String message, byte[] additionalData) throws VirgilException {
        if (SessionStateResolver.isInitiationMessage(message)) {
            InitiationMessage initiationMessage = SecureSession.extractInitiationMessage(message);

            // Added new one time card
            try {
                this.cardsHelper.addCards(this.config.getIdentityCard(), false, 1);
            } catch (VirgilClientException e) {
                return null;
            }

            SecureSession.CardEntry cardEntry = new SecureSession.CardEntry(card.getId(),
                    card.getSnapshotModel().getPublicKeyData());

            Date date = new Date();
            SecureSessionResponder secureSession = new SecureSessionResponder(this.config, this.sessionHelper,
                    additionalData, this.keyHelper, cardEntry, date, getSessionExpirationDate(date));

            secureSession.decrypt(initiationMessage);

            return secureSession;
        } else {
            Message msg = SecureSession.extractMessage(message);

            byte[] sessionId = msg.getSessionId();

            SessionState sessionState = this.sessionHelper.getSessionState(card.getId());
            if (sessionState == null) {
                return null;
            }
            if (!Arrays.equals(sessionId, sessionState.getSessionId())) {
                throw new VirgilClientException("Session not found.");
            }

            SecureSession session = null;
            try {
                session = this.recoverSession(this.config.getIdentityCard(), sessionState);
            } catch (Exception e) {
                // TODO
            }

            return session;
        }
    }

    public void removeSession(String cardId) throws RemoveSessionException {
        try {
            SessionState sessionState = this.sessionHelper.getSessionState(cardId);
            if (sessionState == null) {
                // Session was not found.
                this.removeSessionKeys(cardId);
            } else {
                this.removeSessionKeys(sessionState);
                this.sessionHelper.removeSessionsStates(Arrays.asList(cardId));
            }
        } catch (Exception e) {
            throw new RemoveSessionException(e);
        }
    }

    private void removeSessionKeys(String cardId) throws VirgilException {
        if (this.keyHelper.isEphKeyExists(cardId)) {
            this.keyHelper.removeEphPrivateKey(cardId);
        }
        if (this.keyHelper.isOtKeyExists(cardId)) {
            this.keyHelper.removeOneTimePrivateKey(cardId);
        }
    }

    private void removeSessionKeys(SessionState sessionState) throws VirgilException {
        if (sessionState instanceof InitiatorSessionState) {
            this.removeSessionKeys((InitiatorSessionState) sessionState);
        } else if (sessionState instanceof ResponderSessionState) {
            this.removeSessionKeys((ResponderSessionState) sessionState);
        } else {
            throw new VirgilClientException("Unknown session state.");
        }
    }

    private void removeSessionKeys(InitiatorSessionState sessionState) throws VirgilException {
        this.keyHelper.removeEphPrivateKeyByEntryName(sessionState.getEphKeyName());
    }

    private void removeSessionKeys(ResponderSessionState sessionState) throws VirgilException {
        String otCardId = sessionState.getRecipientOneTimeCardId();
        if (otCardId == null) {
            // Nothing to remove
            return;
        }
        this.keyHelper.removeOneTimePrivateKey(otCardId);
    }

    private void removeExpiredSessionsStates() throws CorruptedSavedSessionException {
        Map<String, SessionState> sessionsStates = this.sessionHelper.getAllSessions();

        Date date = new Date();

        List<String> expiredSessionsStates = new ArrayList<>();

        for (Entry<String, SessionState> sessionState : sessionsStates.entrySet()) {
            if (this.isSessionStateExpired(date, sessionState.getValue())) {
                expiredSessionsStates.add(sessionState.getKey());
            }
        }

        this.sessionHelper.removeSessionsStatesByNames(expiredSessionsStates);
    }

    private void cleanup() throws VirgilException {
        this.removeExpiredSessionsStates();
        Set<String> relevantEphKeys = this.sessionHelper.getEphKeys();
        Set<String> relevantLtCards = this.sessionHelper.getLtCards();
        Set<String> relevantOtCards = this.sessionHelper.getOtCards();

        List<String> otKeys = this.keyHelper.getAllOtCardsIds();

//        List<String> exhaustedCardsIds = this.client.validateOneTimeCards(this.config.getIdentityCard().getId(),
//                otKeys);

        Set<String> relOtCards = new HashSet<>(otKeys);
//        relOtCards.removeAll(exhaustedCardsIds);
        relOtCards.addAll(relevantOtCards);

        this.keyHelper.removeOldKeys(relevantEphKeys, relevantLtCards, relOtCards);
    }

    public void rotateKeys(int desiredNumberOfCards) throws VirgilException {
        this.cleanup();

        // Check ephemeral cards status
        OtcCountResponse status = this.client.getOtcCount(this.config.getIdentityCard().getId());

        // Not enough cards, add more
        int numberOfMissingCards = Math.max(desiredNumberOfCards - status.getActive(), 0);
        if (numberOfMissingCards > 0) {
            this.addMissingCards(numberOfMissingCards);
        }
    }

    private void addMissingCards(int numberOfMissingCards) throws VirgilClientException {
        boolean addLtCard = !this.keyHelper.hasRelevantLtKey();
        this.cardsHelper.addCards(this.config.getIdentityCard(), addLtCard, numberOfMissingCards);
    }

    private Date getSessionExpirationDate(Date date) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.SECOND, this.config.getSessionTtl());

        return cal.getTime();
    }

    public static MessageType getMessageType(String message) {
        if (SessionStateResolver.isInitiationMessage(message)) {
            return MessageType.INITIAL;
        } else if (SessionStateResolver.isRegularMessage(message)) {
            return MessageType.REGULAR;
        }

        return MessageType.UNKNOWN;
    }

}
