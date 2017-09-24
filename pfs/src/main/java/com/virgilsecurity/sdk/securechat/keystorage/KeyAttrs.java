package com.virgilsecurity.sdk.securechat.keystorage;

import java.util.Date;

public class KeyAttrs {

	// Key name
	private String name;

	// Key creation date
	private Date creationDate;

	/**
	 * 
	 */
	public KeyAttrs() {
		super();
	}

	/**
	 * @param name
	 * @param creationDate
	 */
	public KeyAttrs(String name, Date creationDate) {
		super();
		this.name = name;
		this.creationDate = creationDate;
	}

	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @param name
	 *            the name to set
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * @return the creationDate
	 */
	public Date getCreationDate() {
		return creationDate;
	}

	/**
	 * @param creationDate
	 *            the creationDate to set
	 */
	public void setCreationDate(Date creationDate) {
		this.creationDate = creationDate;
	}

}
