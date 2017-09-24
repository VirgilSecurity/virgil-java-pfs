package com.virgilsecurity.sdk.securechat;

import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.UUID;

import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.highlevel.StringEncoding;
import com.virgilsecurity.sdk.highlevel.VirgilBuffer;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

public class TestUtils {

	public static byte[] generateBytes(int size) {
		byte[] bytes = new byte[size];
		new Random().nextBytes(bytes);
		return bytes;
	}
	
	public static String generateCardId() {
		return UUID.randomUUID().toString();
	}
	
	public static String generateKeyName() {
		return UUID.randomUUID().toString();
	}

	public static boolean isInList(final List<byte[]> list, final byte[] candidate) {

		for (final byte[] item : list) {
			if (Arrays.equals(item, candidate)) {
				return true;
			}
		}
		return false;
	}
	
	public static CardModel importCard(String exportedCard) {
		VirgilBuffer bufferCard = VirgilBuffer.from(exportedCard, StringEncoding.Base64);
		CardModel importedCardModel = ConvertionUtils.getGson().fromJson(bufferCard.toString(), CardModel.class);

		return importedCardModel;
	}

}
