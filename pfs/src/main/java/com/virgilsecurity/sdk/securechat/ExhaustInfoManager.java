package com.virgilsecurity.sdk.securechat;

import java.util.logging.Logger;

import com.virgilsecurity.sdk.securechat.model.ExhaustInfo;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

public class ExhaustInfoManager {

	private static final Logger log = Logger.getLogger(ExhaustInfoManager.class.getName());

	private String cardId;
	private UserDataStorage storage;

	/**
	 * @param cardId
	 * @param storage
	 */
	public ExhaustInfoManager(String cardId, UserDataStorage storage) {
		super();
		this.cardId = cardId;
		this.storage = storage;
	}

	public ExhaustInfo getKeysExhaustInfo() {
		log.fine("Getting exhaust info");

		String entry = storage.getData(this.cardId, this.getExhaustEntryKey());
		if (StringUtils.isBlank(entry)) {
			return new ExhaustInfo();
		}
		ExhaustInfo info = ConvertionUtils.getGson().fromJson(entry, ExhaustInfo.class);

		return info;
	}

	public void saveKeysExhaustInfo(ExhaustInfo keysExhaustInfo) {
		log.fine("Saving exhaust info");

		this.storage.addData(this.cardId, this.getExhaustEntryKey(), ConvertionUtils.getGson().toJson(keysExhaustInfo));
	}

	private String getExhaustEntryKey() {
		return String.format("VIRGIL.EXHAUSTINFO.OWNER=%s", this.cardId);
	}
}
