package com.virgilsecurity.sdk.securechat;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;
import java.util.Random;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.securechat.impl.DefaultUserDataStorage;
import com.virgilsecurity.sdk.securechat.model.SessionState;

public class SessionStorageManagerTest {

	private SessionStorageManager sessionStorageManager;
	private String cardId;
	private String recipientCardId1;
	private String recipientCardId2;
	private byte[] sessionId1;
	private byte[] sessionId2;
	private byte[] sessionId3;
	private byte[] sessionId4;
	private SessionState sessionState1;
	private SessionState sessionState2;
	private SessionState sessionState3;
	private SessionState sessionState4;

	@Before
	public void setUp() {
		this.cardId = UUID.randomUUID().toString();
		this.recipientCardId1 = UUID.randomUUID().toString();
		this.recipientCardId2 = UUID.randomUUID().toString();

		UserDataStorage storage = new DefaultUserDataStorage();
		this.sessionStorageManager = new SessionStorageManager(this.cardId, storage);

		this.sessionId1 = TestUtils.generateBytes(16);
		this.sessionId2 = TestUtils.generateBytes(16);
		this.sessionId3 = TestUtils.generateBytes(16);
		this.sessionId4 = TestUtils.generateBytes(16);

		Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MILLISECOND, 0);

		Date now = cal.getTime();
		cal.add(Calendar.SECOND, 5);

		this.sessionState1 = new SessionState(this.sessionId1, now, now, null);
		this.sessionState2 = new SessionState(this.sessionId2, cal.getTime(), now, null);
		this.sessionState3 = new SessionState(this.sessionId3, now, now, null);
		this.sessionState4 = new SessionState(this.sessionId4, now, now, null);

		this.sessionStorageManager.addSessionState(this.sessionState1, this.recipientCardId1);
		this.sessionStorageManager.addSessionState(this.sessionState2, this.recipientCardId1);
		this.sessionStorageManager.addSessionState(this.sessionState3, this.recipientCardId2);
		this.sessionStorageManager.addSessionState(this.sessionState4, this.recipientCardId2);
	}

	@Test
	public void getSession() {
		SessionState sessionState = this.sessionStorageManager.getSessionState(this.recipientCardId1,
				this.sessionState1.getSessionId());
		assertNotNull(sessionState);
		assertEquals(this.sessionState1, sessionState);
	}

	@Test
	public void getNonExistentSession() {
		SessionState sessionState = this.sessionStorageManager.getSessionState(this.recipientCardId2,
				this.sessionState1.getSessionId());
		assertNull(sessionState);
	}

	@Test
	public void getAllSessionsForRecipient() {
		List<byte[]> sessionStatesIds = this.sessionStorageManager.getSessionStatesIds(this.recipientCardId1);
		assertNotNull(sessionStatesIds);
		assertEquals(2, sessionStatesIds.size());

		assertTrue(TestUtils.isInList(sessionStatesIds, sessionState1.getSessionId()));
		assertTrue(TestUtils.isInList(sessionStatesIds, sessionState2.getSessionId()));
	}

	@Test
	public void getAllSessions() {
		List<Entry<String, SessionState>> savedStates = this.sessionStorageManager.getAllSessionsStates();
		assertNotNull(savedStates);
		assertEquals(4, savedStates.size());

		assertTrue(savedStates.contains(new AbstractMap.SimpleEntry(this.recipientCardId1, this.sessionState1)));
		assertTrue(savedStates.contains(new AbstractMap.SimpleEntry(this.recipientCardId1, this.sessionState2)));
		assertTrue(savedStates.contains(new AbstractMap.SimpleEntry(this.recipientCardId2, this.sessionState3)));
		assertTrue(savedStates.contains(new AbstractMap.SimpleEntry(this.recipientCardId2, this.sessionState4)));

		assertFalse(savedStates.contains(new AbstractMap.SimpleEntry(this.recipientCardId1, this.sessionState4)));
	}

	@Test
	public void getNewestSessionState() {
		SessionState sessionState = this.sessionStorageManager.getNewestSessionState(this.recipientCardId1);
		assertNotNull(sessionState);
		assertEquals(this.sessionState2, sessionState);
	}

	@Test
	public void removeSessionState() {
		this.sessionStorageManager.removeSessionState(this.recipientCardId1, this.sessionState1.getSessionId());

		SessionState sessionState = this.sessionStorageManager.getSessionState(this.recipientCardId1,
				this.sessionState1.getSessionId());

		assertNull(sessionState);
	}

	@Test
	public void removeSessionStates() {
		List<Entry<String, byte[]>> pairs = new ArrayList<>();
		pairs.add(
				new AbstractMap.SimpleEntry<String, byte[]>(this.recipientCardId1, this.sessionState1.getSessionId()));
		this.sessionStorageManager.removeSessionsStates(pairs);

		assertNull(sessionStorageManager.getSessionState(this.recipientCardId1, this.sessionState1.getSessionId()));
		assertNotNull(sessionStorageManager.getSessionState(this.recipientCardId1, this.sessionState2.getSessionId()));
		assertNotNull(sessionStorageManager.getSessionState(this.recipientCardId2, this.sessionState3.getSessionId()));
		assertNotNull(sessionStorageManager.getSessionState(this.recipientCardId2, this.sessionState4.getSessionId()));

		pairs = new ArrayList<>();
		pairs.add(
				new AbstractMap.SimpleEntry<String, byte[]>(this.recipientCardId1, this.sessionState2.getSessionId()));
		pairs.add(
				new AbstractMap.SimpleEntry<String, byte[]>(this.recipientCardId2, this.sessionState3.getSessionId()));
		pairs.add(
				new AbstractMap.SimpleEntry<String, byte[]>(this.recipientCardId2, this.sessionState4.getSessionId()));
		this.sessionStorageManager.removeSessionsStates(pairs);

		assertNull(sessionStorageManager.getSessionState(this.recipientCardId1, this.sessionState2.getSessionId()));
		assertNull(sessionStorageManager.getSessionState(this.recipientCardId2, this.sessionState3.getSessionId()));
		assertNull(sessionStorageManager.getSessionState(this.recipientCardId2, this.sessionState4.getSessionId()));
	}

}
