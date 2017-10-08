package com.virgilsecurity.sdk.securechat;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import com.virgilsecurity.sdk.securechat.model.InitiationMessage;
import com.virgilsecurity.sdk.securechat.model.Message;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

public class CompatibilityTest {

	@Test
	public void initiationMessage() throws IOException {
		String sample = IOUtils
				.toString(this.getClass().getClassLoader().getResourceAsStream("InitiationMessageExample.json"));
		InitiationMessage initiationMessage = ConvertionUtils.getGson().fromJson(sample, InitiationMessage.class);

		assertEquals("1d6dfd3624c9211071e78dc950c7a69f7dfcbccc404f69a08fc5fd791c1e299d",
				initiationMessage.getResponderIcId());
		assertArrayEquals(ConvertionUtils.base64ToBytes("qQlrx2niPx+pQ+xCcPTnrih46ChEGp/XNQ5IaWa9bND+9UKpVw=="),
				initiationMessage.getCipherText());
		assertEquals("dd58dcccb4e521b71e9faa6d78371c57d1540fb9d1593f57fe75b14b0d66b47f",
				initiationMessage.getResponderOtcId());
		assertEquals("555eb3311d1a29043300df8d71132da766f373d2cb67d42feb2780572f062218",
				initiationMessage.getResponderLtcId());
		assertArrayEquals(ConvertionUtils.base64ToBytes("MCowBQYDK2VwAyEA2QL4ri94/bwAI5sBabv//mNylwphNaIH9i+XcHyC31Y="),
				initiationMessage.getEphPublicKey());
		assertArrayEquals(
				ConvertionUtils.base64ToBytes(
						"MFEwDQYJYIZIAWUDBAICBQAEQBzMAHMRw+OLGoC15iyVJzCjl3PvX5tFjl+/xcUdAAWLl6bBkzsxWa3Xi06X9CZXLlOw9LL0KKRSxIJ7flZAFwo="),
				initiationMessage.getEphPublicKeySignature());
		assertArrayEquals(ConvertionUtils.base64ToBytes("9B+pj/IKvXD5dw4zGnV5+g=="), initiationMessage.getSalt());
		assertEquals("20c3374b6643841cd2da8277ee63ec3ecd4b10189b9e189102854112cc6755e7",
				initiationMessage.getInitiatorIcId());
	}

	@Test
	public void weakInitiationMessage() throws IOException {
		String sample = IOUtils
				.toString(this.getClass().getClassLoader().getResourceAsStream("InitiationWeakMessageExample.json"));
		InitiationMessage initiationMessage = ConvertionUtils.getGson().fromJson(sample, InitiationMessage.class);

		assertEquals("799d87cbc0022c5b10ef026da626e2863404228cb66a52009ee964a018724292",
				initiationMessage.getResponderIcId());
		assertArrayEquals(ConvertionUtils.base64ToBytes("mhHJqPsr/oXdVftZMRjyKVLmeotdicg0"),
				initiationMessage.getCipherText());
		assertNull(initiationMessage.getResponderOtcId());
		assertEquals("6911a2417a4ddd71721596c2b2db2c16062631f9e2397d2381266ea0736e3c44",
				initiationMessage.getResponderLtcId());
		assertArrayEquals(ConvertionUtils.base64ToBytes("MCowBQYDK2VwAyEAit9SQ95k4L5fJTrg3m9O0D02S9ec468+fJ3tw4do7jU="),
				initiationMessage.getEphPublicKey());
		assertArrayEquals(
				ConvertionUtils.base64ToBytes(
						"MFEwDQYJYIZIAWUDBAICBQAEQI0ZjJWiC6T6rVixYfyj1B4uY93hmohuzbob1QU3oiEDQ4RzS3N874p0+dxMX+SLE29OMIk9I4A54r8fiABUbwQ="),
				initiationMessage.getEphPublicKeySignature());
		assertArrayEquals(ConvertionUtils.base64ToBytes("XIM/ZoEGyYYd5FUR6E1jIA=="), initiationMessage.getSalt());
		assertEquals("ea34ef3ea70f0b61ea02e40f358ff9381ac6fdec59377513c196cde4b45df988",
				initiationMessage.getInitiatorIcId());
	}

	@Test
	public void regularMessage() throws IOException {
		String sample = IOUtils
				.toString(this.getClass().getClassLoader().getResourceAsStream("RegularMessageExample.json"));
		Message message = ConvertionUtils.getGson().fromJson(sample, Message.class);

		assertArrayEquals(ConvertionUtils.base64ToBytes("NttiPDghzJM6nN26B0dlusMvh6RxApJdeRWAXQ=="),
				message.getCipherText());
		assertArrayEquals(ConvertionUtils.base64ToBytes("/p05lK7+QpswdTDOvcaRMg=="), message.getSalt());
		assertArrayEquals(ConvertionUtils.base64ToBytes("vdPsqVXhmW9ysgoEIbWTl58yV+AC+vAeFsxiznC2avc="),
				message.getSessionId());
	}

}
