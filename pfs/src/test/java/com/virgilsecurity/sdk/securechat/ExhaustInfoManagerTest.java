package com.virgilsecurity.sdk.securechat;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.securechat.impl.DefaultUserDataStorage;
import com.virgilsecurity.sdk.securechat.model.ExhaustInfo;
import com.virgilsecurity.sdk.securechat.model.ExhaustInfo.ExhaustInfoEntry;
import com.virgilsecurity.sdk.securechat.model.ExhaustInfo.SessionExhaustInfo;

public class ExhaustInfoManagerTest {

	private ExhaustInfoManager exhaustInfoManager;
	private String cardId;

	@Before
	public void setUp() {
		cardId = UUID.randomUUID().toString();
		UserDataStorage storage = new DefaultUserDataStorage();
		exhaustInfoManager = new ExhaustInfoManager(cardId, storage);
	}

	@Test
	public void getEmptyInfo() {
		ExhaustInfo exhaustInfo = exhaustInfoManager.getKeysExhaustInfo();

		assertNotNull(exhaustInfo);
		assertTrue(exhaustInfo.getLtc().isEmpty());
		assertTrue(exhaustInfo.getOtc().isEmpty());
		assertTrue(exhaustInfo.getSessions().isEmpty());
	}

	@Test
	public void saveInfo() {
		Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MILLISECOND, 0);
		Date now = cal.getTime();

		List<ExhaustInfoEntry> otc = Arrays.asList(new ExhaustInfoEntry(UUID.randomUUID().toString(), now),
				new ExhaustInfoEntry(UUID.randomUUID().toString(), now));

		List<ExhaustInfoEntry> ltc = Arrays.asList(new ExhaustInfoEntry(UUID.randomUUID().toString(), now),
				new ExhaustInfoEntry(UUID.randomUUID().toString(), now),
				new ExhaustInfoEntry(UUID.randomUUID().toString(), now));

		byte[] sessionId = TestUtils.generateBytes(16);
		List<SessionExhaustInfo> sessions = Arrays
				.asList(new SessionExhaustInfo(sessionId, UUID.randomUUID().toString(), now));

		ExhaustInfo info = new ExhaustInfo(otc, ltc, sessions);

		exhaustInfoManager.saveKeysExhaustInfo(info);

		ExhaustInfo exhaustInfo = exhaustInfoManager.getKeysExhaustInfo();

		assertNotNull(exhaustInfo);
		assertEquals(otc, exhaustInfo.getOtc());
		assertEquals(ltc, exhaustInfo.getLtc());
		assertEquals(sessions, exhaustInfo.getSessions());
	}

}
