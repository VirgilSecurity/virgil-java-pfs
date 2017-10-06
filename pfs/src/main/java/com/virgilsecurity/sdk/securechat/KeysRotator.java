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

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.Semaphore;
import java.util.logging.Logger;

import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.pfs.VirgilPFSClient;
import com.virgilsecurity.sdk.pfs.model.response.CardStatus;
import com.virgilsecurity.sdk.securechat.keystorage.KeyAttrs;
import com.virgilsecurity.sdk.securechat.model.ExhaustInfo;
import com.virgilsecurity.sdk.securechat.model.ExhaustInfo.ExhaustInfoEntry;
import com.virgilsecurity.sdk.securechat.model.ExhaustInfo.SessionExhaustInfo;
import com.virgilsecurity.sdk.securechat.model.SessionState;
import com.virgilsecurity.sdk.securechat.utils.ArrayUtils;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * This class provides key rotation functionality.
 * 
 * @author Andrii Iakovenko
 *
 */
public class KeysRotator {
	private static final Logger log = Logger.getLogger(KeysRotator.class.getName());
	static final int SECONDS_IN_DAY = 24 * 60 * 60;

	private CardModel identityCard;
	private int exhaustedOneTimeCardTtl;
	private int expiredSessionTtl;
	private int longTermKeysTtl;
	private int expiredLongTermCardTtl;
	private EphemeralCardsReplenisher ephemeralCardsReplenisher;
	private SessionStorageManager sessionStorageManager;
	private KeyStorageManager keyStorageManager;
	private ExhaustInfoManager exhaustInfoManager;
	private VirgilPFSClient pfsClient;
	private Semaphore semaphore = new Semaphore(1);

	public KeysRotator(CardModel card, int exhaustedOneTimeCardTtl, int expiredSessionTtl, int longTermKeysTtl,
			int expiredLongTermCardTtl, EphemeralCardsReplenisher replenisher,
			SessionStorageManager sessionStorageManager, KeyStorageManager keyStorageManager,
			ExhaustInfoManager exhaustInfoManager, VirgilPFSClient pfsClient) {
		this.identityCard = card;
		this.exhaustedOneTimeCardTtl = exhaustedOneTimeCardTtl;
		this.expiredSessionTtl = expiredSessionTtl;
		this.longTermKeysTtl = longTermKeysTtl;
		this.expiredLongTermCardTtl = expiredLongTermCardTtl;
		this.ephemeralCardsReplenisher = replenisher;
		this.sessionStorageManager = sessionStorageManager;
		this.keyStorageManager = keyStorageManager;
		this.exhaustInfoManager = exhaustInfoManager;
		this.pfsClient = pfsClient;
	}

	private void cleanup() {
		log.fine("Cleanup started.");
		Date now = new Date();

		Entry<ExhaustInfo, List<String>> entry = processExhaustedStuff(now);
		ExhaustInfo updatedExhaustInfo = entry.getKey();
		List<String> otCardsToCheck = entry.getValue();

		List<String> exhaustedCardsIds = this.pfsClient.validateOneTimeCards(this.identityCard.getId(), otCardsToCheck);

		this.updateExhaustInfo(now, updatedExhaustInfo, exhaustedCardsIds);
	}

	private Date minusSeconds(Date now, int ttl) {
		Calendar cal = Calendar.getInstance();
		cal.setTime(now);
		cal.add(Calendar.SECOND, -ttl);

		return cal.getTime();
	}

	private Entry<ExhaustInfo, List<String>> processExhaustedStuff(Date now) {
		log.fine("Processing exhausted stuff.");

		ExhaustInfo exhaustInfo = exhaustInfoManager.getKeysExhaustInfo();
		List<Entry<String, SessionState>> allSessionStates = sessionStorageManager.getAllSessionsStates();
		Map<String, List<KeyAttrs>> keys = keyStorageManager.getAllKeysAttrs();
		List<KeyAttrs> otKeys = keys.get(KeyStorageManager.OT_KEYS);
		List<KeyAttrs> ltKeys = keys.get(KeyStorageManager.LT_KEYS);
		List<KeyAttrs> sessionKeys = keys.get(KeyStorageManager.SESSION_KEYS);

		exhaustInfo = removeExpiredLtKeys(now, ltKeys, exhaustInfo);
		exhaustInfo = removeOrphanedOtcs(now, otKeys, exhaustInfo);

		List<String> newOtKeysIds = new ArrayList<>(exhaustInfo.getOtc().size());
		for (ExhaustInfoEntry infoEntry : exhaustInfo.getOtc()) {
			newOtKeysIds.add(infoEntry.getIdentifier());
		}
		List<String> otKeysIdsToCheck = new ArrayList<>();
		for (KeyAttrs key : otKeys) {
			if (!newOtKeysIds.contains(key.getName())) {
				otKeysIdsToCheck.add(key.getName());
			}
		}

		exhaustInfo = removeExpiredSessions(now, allSessionStates, exhaustInfo);
		removeOrhpanedSessionKeys(sessionKeys, allSessionStates);

		return new AbstractMap.SimpleEntry<ExhaustInfo, List<String>>(exhaustInfo, otKeysIdsToCheck);
	}

	private ExhaustInfo removeExpiredLtKeys(Date now, List<KeyAttrs> ltKeys, ExhaustInfo exhaustInfo) {
		log.fine("Removing expired ltc.");

		// Remove lt keys that have expired some time ago
		List<String> ltcIdsToRemove = new ArrayList<>();
		Date exDate = minusSeconds(now, this.expiredLongTermCardTtl);
		for (ExhaustInfoEntry key : exhaustInfo.getLtc()) {
			if (exDate.after(key.getExhaustDate())) {
				ltcIdsToRemove.add(key.getIdentifier());
			}
		}

		keyStorageManager.removeLtPrivateKeys(ltcIdsToRemove);

		// Updated lt keys info
		List<KeyAttrs> ltKeysUpdated = new LinkedList<>();
		for (KeyAttrs key : ltKeys) {
			if (!ltcIdsToRemove.contains(key.getName())) {
				ltKeysUpdated.add(key);
			}
		}

		// Update exhaust info:
		// Clear removed keys
		List<ExhaustInfoEntry> newLtKeys = new LinkedList<>();
		for (ExhaustInfoEntry infoEntry : exhaustInfo.getLtc()) {
			if (!ltcIdsToRemove.contains(infoEntry.getIdentifier())) {
				newLtKeys.add(infoEntry);
			}
		}

		// Add lt keys that have expired recently
		List<String> newLtKeysIds = new LinkedList<>();
		for (ExhaustInfoEntry key : newLtKeys) {
			newLtKeysIds.add(key.getIdentifier());
		}

		exDate = minusSeconds(now, this.longTermKeysTtl);
		for (KeyAttrs key : ltKeysUpdated) {
			if (exDate.after(key.getCreationDate()) && !newLtKeysIds.contains(key.getName())) {
				ExhaustInfoEntry infoEntry = new ExhaustInfoEntry(key.getName(), now);
				newLtKeys.add(infoEntry);
			}
		}

		// Update exhaust info
		return new ExhaustInfo(exhaustInfo.getOtc(), newLtKeys, exhaustInfo.getSessions());
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private ExhaustInfo removeExpiredSessions(Date now, List<Map.Entry<String, SessionState>> allSessions,
			ExhaustInfo exhaustInfo) {
		log.fine("Removing expired sessions.");

		List<byte[]> sessionsIds = new LinkedList<>();
		for (Map.Entry<String, SessionState> entry : allSessions) {
			sessionsIds.add(entry.getValue().getSessionId());
		}

		// Remove expired sessions
		Date exDate = minusSeconds(now, this.expiredSessionTtl);
		// List<SessionExhaustInfo> sessionInfosToRemove = new LinkedList<>();
		List<Map.Entry<String, byte[]>> sessionStatesToRemove = new LinkedList<>();
		List<byte[]> sessionIdsToRemove = new LinkedList<>();
		for (SessionExhaustInfo sessionInfo : exhaustInfo.getSessions()) {
			if (exDate.after(sessionInfo.getExhaustDate())
					&& ArrayUtils.isInList(sessionsIds, sessionInfo.getIdentifier())) {
				// sessionInfosToRemove.add(sessionInfo);
				sessionIdsToRemove.add(sessionInfo.getIdentifier());

				sessionStatesToRemove
						.add(new AbstractMap.SimpleEntry(sessionInfo.getCardId(), sessionInfo.getIdentifier()));
			}
		}

		keyStorageManager.removeSessionKeys(sessionIdsToRemove);
		sessionStorageManager.removeSessionsStates(sessionStatesToRemove);

		// Update sessions info
		List<Entry<String, SessionState>> allSessionsUpdated = new LinkedList<>();
		for (Entry<String, SessionState> entry : allSessions) {
			if (!ArrayUtils.isInList(sessionIdsToRemove, entry.getValue().getSessionId())) {
				allSessionsUpdated.add(entry);
			}
		}

		// Update exhaust info:
		// Clear removed keys
		List<SessionExhaustInfo> newSessions = new ArrayList<>();
		List<byte[]> newSessionsIds = new LinkedList<>();
		for (SessionExhaustInfo sessionInfo : exhaustInfo.getSessions()) {
			if (!ArrayUtils.isInList(sessionIdsToRemove, sessionInfo.getIdentifier())) {
				newSessions.add(sessionInfo);
				newSessionsIds.add(sessionInfo.getIdentifier());
			}
		}

		// Add recently expired keys
		for (Entry<String, SessionState> entry : allSessionsUpdated) {
			SessionState session = entry.getValue();
			if (session.isExpired(now) && !ArrayUtils.isInList(newSessionsIds, session.getSessionId())) {
				newSessions.add(new SessionExhaustInfo(session.getSessionId(), entry.getKey(), now));
			}
		}

		// Updated exhaust info
		return new ExhaustInfo(exhaustInfo.getOtc(), exhaustInfo.getLtc(), newSessions);
	}

	private void removeOrhpanedSessionKeys(List<KeyAttrs> sessionKeys, List<Entry<String, SessionState>> allSessions) {
		log.fine("Removing orphaned session keys.");

		List<byte[]> allSessionsIds = new LinkedList<>();
		for (Entry<String, SessionState> entry : allSessions) {
			allSessionsIds.add(entry.getValue().getSessionId());
		}
		List<byte[]> orphanedSessionKeysIds = new LinkedList<>();
		for (KeyAttrs keyAttrs : sessionKeys) {
			byte[] sessionId = ConvertionUtils.base64ToBytes(keyAttrs.getName());
			if (!ArrayUtils.isInList(allSessionsIds, sessionId)) {
				orphanedSessionKeysIds.add(sessionId);
			}
		}

		if (!orphanedSessionKeysIds.isEmpty()) {
			log.warning(String.format("WARNING: orphaned session keys found: %d", orphanedSessionKeysIds.size()));
			keyStorageManager.removeSessionKeys(orphanedSessionKeysIds);
		}
	}

	private ExhaustInfo removeOrphanedOtcs(Date now, List<KeyAttrs> otKeys, ExhaustInfo exhaustInfo) {
		log.fine("Removing orphaned otcs.");

		List<String> otKeysIds = new LinkedList<>();
		for (KeyAttrs key : otKeys) {
			otKeysIds.add(key.getName());
		}

		// Remove ot keys that have been used some time ago
		Date exDate = minusSeconds(now, this.exhaustedOneTimeCardTtl);

		List<String> otcIdsToRemove = new LinkedList<>();
		for (ExhaustInfoEntry infoEntry : exhaustInfo.getOtc()) {
			if (exDate.after(infoEntry.getExhaustDate()) && otKeysIds.contains(infoEntry.getIdentifier())) {
				otcIdsToRemove.add(infoEntry.getIdentifier());
			}
		}

		if (!otcIdsToRemove.isEmpty()) {
			log.warning(String.format("WARNING: orphaned otcs found: %d", otcIdsToRemove.size()));
			keyStorageManager.removeOtPrivateKeys(otcIdsToRemove);
		}

		// Updated exhaust info
		List<ExhaustInfoEntry> newOtKeys = new LinkedList<>();
		for (ExhaustInfoEntry infoEntry : exhaustInfo.getOtc()) {
			if (otcIdsToRemove.contains(infoEntry.getIdentifier())) {
				newOtKeys.add(infoEntry);
			}
		}

		return new ExhaustInfo(newOtKeys, exhaustInfo.getLtc(), exhaustInfo.getSessions());
	}

	/**
	 * Rotate keys.
	 * 
	 * @param desiredNumberOfCards
	 *            the desired number of cards which should be available.
	 */
	public void rotateKeys(int desiredNumberOfCards) {
		log.fine("Started keys' rotation");
		try {
			semaphore.acquire();

			log.fine("Get OTC status.");
			CardStatus status = pfsClient.getCardStatus(this.identityCard.getId());
			int numberOfMissingCards = Math.max(desiredNumberOfCards - status.getActive(), 0);

			// Cleanup
			log.fine("Cleanup");
			cleanup();

			log.fine("Adding new cards.");
			boolean addLtCard = !keyStorageManager.hasRelevantLtKey(this.longTermKeysTtl);
			if (numberOfMissingCards > 0 || addLtCard) {
				ephemeralCardsReplenisher.addCards(addLtCard, numberOfMissingCards);
			}
		} catch (InterruptedException e) {
			log.severe("Rotate keys interrupted");
		} finally {
			semaphore.release();
		}
	}

	private void updateExhaustInfo(Date now, ExhaustInfo exhaustInfo, List<String> exhaustedCardsIds) {
		List<ExhaustInfoEntry> newOtc = exhaustInfo.getOtc();
		for (String exhaustedCardsId : exhaustedCardsIds) {
			ExhaustInfoEntry infoEntry = new ExhaustInfoEntry(exhaustedCardsId, now);
			newOtc.add(infoEntry);
		}
		ExhaustInfo newExhaustInfo = new ExhaustInfo(newOtc, exhaustInfo.getLtc(), exhaustInfo.getSessions());

		this.exhaustInfoManager.saveKeysExhaustInfo(newExhaustInfo);
	}
}
