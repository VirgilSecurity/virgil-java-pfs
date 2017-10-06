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
package com.virgilsecurity.sdk.securechat.model;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Date;

import com.google.gson.annotations.SerializedName;

/**
 * @author Andrii Iakovenko
 *
 */
public class SessionState implements Serializable {

	private static final long serialVersionUID = 6554793364131958950L;

	@SerializedName("creation_date")
	private Date creationDate;

	@SerializedName("expiration_date")
	private Date expirationDate;

	@SerializedName("session_id")
	private byte[] sessionId;

	@SerializedName("additional_data")
	private byte[] additionalData;

	/**
	 * Create new instance of {@link SessionState}.
	 */
	public SessionState() {
	}

	/**
	 * Create new instance of {@link SessionState}.
	 * 
	 * @param sessionId
	 * @param creationDate
	 * @param expirationDate
	 * @param additionalData
	 * 
	 */
	public SessionState(byte[] sessionId, Date creationDate, Date expirationDate, byte[] additionalData) {
		this.creationDate = creationDate;
		this.expirationDate = expirationDate;
		this.sessionId = sessionId;
		this.additionalData = additionalData;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SessionState other = (SessionState) obj;
		if (!Arrays.equals(additionalData, other.additionalData))
			return false;
		if (creationDate == null) {
			if (other.creationDate != null)
				return false;
		} else if (!creationDate.equals(other.creationDate))
			return false;
		if (expirationDate == null) {
			if (other.expirationDate != null)
				return false;
		} else if (!expirationDate.equals(other.expirationDate))
			return false;
		if (!Arrays.equals(sessionId, other.sessionId))
			return false;
		return true;
	}

	/**
	 * @return the additionalData
	 */
	public byte[] getAdditionalData() {
		return additionalData;
	}

	/**
	 * @return the creationDate
	 */
	public Date getCreationDate() {
		return creationDate;
	}

	/**
	 * @return the expirationDate
	 */
	public Date getExpirationDate() {
		return expirationDate;
	}

	/**
	 * @return the sessionId
	 */
	public byte[] getSessionId() {
		return sessionId;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(additionalData);
		result = prime * result + ((creationDate == null) ? 0 : creationDate.hashCode());
		result = prime * result + ((expirationDate == null) ? 0 : expirationDate.hashCode());
		result = prime * result + Arrays.hashCode(sessionId);
		return result;
	}

	/**
	 * Checks if session already expired.
	 * 
	 * @return {@code true} if session expired at the moment.
	 */
	public boolean isExpired() {
		return isExpired(new Date());
	}

	/**
	 * Checks if session expired to the date.
	 * 
	 * @param date
	 *            the date.
	 * @return {@code true} if session expired to the date {@code date}.
	 */
	public boolean isExpired(Date date) {
		if (this.expirationDate == null) {
			return false;
		}
		return this.expirationDate.before(date);
	}

	/**
	 * @param additionalData
	 *            the additionalData to set
	 */
	public void setAdditionalData(byte[] additionalData) {
		this.additionalData = additionalData;
	}

	/**
	 * @param creationDate
	 *            the creationDate to set
	 */
	public void setCreationDate(Date creationDate) {
		this.creationDate = creationDate;
	}

	/**
	 * @param expirationDate
	 *            the expirationDate to set
	 */
	public void setExpirationDate(Date expirationDate) {
		this.expirationDate = expirationDate;
	}

	/**
	 * @param sessionId
	 *            the sessionId to set
	 */
	public void setSessionId(byte[] sessionId) {
		this.sessionId = sessionId;
	}

}
