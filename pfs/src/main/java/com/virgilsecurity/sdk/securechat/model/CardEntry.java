package com.virgilsecurity.sdk.securechat.model;

public class CardEntry {

	private String identifier;
	private byte[] publicKeyData;

	/**
	 * Create new instance of {@link CardEntry}.
	 * 
	 * @param identifier
	 * @param publicKeyData
	 */
	public CardEntry(String identifier, byte[] publicKeyData) {
		super();
		this.identifier = identifier;
		this.publicKeyData = publicKeyData;
	}

	/**
	 * @return the identifier
	 */
	public String getIdentifier() {
		return identifier;
	}

	/**
	 * @param identifier
	 *            the identifier to set
	 */
	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	/**
	 * @return the publicKeyData
	 */
	public byte[] getPublicKeyData() {
		return publicKeyData;
	}

	/**
	 * @param publicKeyData
	 *            the publicKeyData to set
	 */
	public void setPublicKeyData(byte[] publicKeyData) {
		this.publicKeyData = publicKeyData;
	}

}
