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
package com.virgilsecurity.sdk.securechat.session;

import java.util.Arrays;
import java.util.Date;

import com.virgilsecurity.crypto.VirgilPFS;
import com.virgilsecurity.crypto.VirgilPFSEncryptedMessage;
import com.virgilsecurity.crypto.VirgilPFSSession;
import com.virgilsecurity.sdk.securechat.exceptions.NoSessionException;
import com.virgilsecurity.sdk.securechat.model.InitiationMessage;
import com.virgilsecurity.sdk.securechat.model.Message;
import com.virgilsecurity.sdk.securechat.session.SessionInitializer.FirstMessageGenerator;
import com.virgilsecurity.sdk.securechat.utils.GsonUtils;
import com.virgilsecurity.sdk.securechat.utils.SessionStateResolver;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureSession {

	private Date expirationDate;
	private VirgilPFS pfs;
	private VirgilPFSSession pfsSession;
	private FirstMessageGenerator firstMsgGenerator;

	public SecureSession() {
		this.pfs = new VirgilPFS();
	}

	public SecureSession(VirgilPFSSession pfsSession, Date expirationDate, FirstMessageGenerator firstMsgGenerator) {
		this();
		this.expirationDate = expirationDate;
		this.pfsSession = pfsSession;
		this.pfs.setSession(pfsSession);
		this.firstMsgGenerator = firstMsgGenerator;
	}

	/**
	 * Checks if this session is expired at {@docRoot theDate}.
	 * 
	 * @param theDate
	 * @return {@code true} if session if expired.
	 */
	public boolean isExpired(Date theDate) {
		if (this.expirationDate == null) {
			return false;
		}
		return theDate.after(this.expirationDate);
	}

	/**
	 * Checks if this session is expired.
	 * 
	 * @return {@code true} if session if expired.
	 */
	public boolean isExpired() {
		return this.isExpired(new Date());
	}

	/**
	 * Decrypts message.
	 * 
	 * @param encryptedMessage
	 *            the encrypted message.
	 * @return the decrypted message.
	 */
	public String decrypt(Message encryptedMessage) {
		VirgilPFSEncryptedMessage message = new VirgilPFSEncryptedMessage(encryptedMessage.getSessionId(),
				encryptedMessage.getSalt(), encryptedMessage.getCipherText());

		byte[] msgData = this.pfs.decrypt(message);
		String str = ConvertionUtils.toString(msgData);
		return str;
	}

	/**
	 * Decrypts message.
	 * 
	 * @param encryptedMessage
	 *            the encrypted message.
	 * @return the decrypted message.
	 */
	public String decrypt(String encryptedMessage) {
		Message message = null;
		if (SessionStateResolver.isInitiationMessage(encryptedMessage)) {
			InitiationMessage initiationMessage = SecureSession.extractInitiationMessage(encryptedMessage);
			message = new Message(this.pfsSession.getIdentifier(), initiationMessage.getSalt(),
					initiationMessage.getCipherText());
		} else {
			message = SecureSession.extractMessage(encryptedMessage);
		}
		return this.decrypt(message);
	}

	/**
	 * Encrypts message.
	 * 
	 * @param message
	 *            the message to encrypt.
	 * @return the encrypted message.
	 * @throws NoSessionException
	 */
	public String encrypt(String message) throws NoSessionException {

		// Initiation message
		if (this.firstMsgGenerator != null) {
			String encryptedMessage = firstMsgGenerator.generate(this, message);
			this.firstMsgGenerator = null;
			return encryptedMessage;
		}

		byte[] messageData = ConvertionUtils.toBytes(message);

		VirgilPFSEncryptedMessage encryptedMessage = this.pfs.encrypt(messageData);

		Message msg = new Message(encryptedMessage.getSessionIdentifier(), encryptedMessage.getSalt(),
				encryptedMessage.getCipherText());

		String msgStr = GsonUtils.getGson().toJson(msg);

		return msgStr;
	}

	public String encryptInitiationMessage(String message, byte[] ephPublicKeyData, byte[] ephPublicKeySignature,
			String initiatorIcId, String responderIcId, String responderLtcId, String responderOtcId) {
		byte[] messageData = ConvertionUtils.toBytes(message);

		VirgilPFSEncryptedMessage encryptedMessage = this.pfs.encrypt(messageData);

		InitiationMessage initMsg = new InitiationMessage(initiatorIcId, responderIcId, responderLtcId, responderOtcId,
				ephPublicKeyData, ephPublicKeySignature, encryptedMessage.getSalt(), encryptedMessage.getCipherText());

		String msg = ConvertionUtils.getGson().toJson(initMsg);
		return msg;
	}

	public static InitiationMessage extractInitiationMessage(byte[] message) {
		String json = ConvertionUtils.toString(message);
		InitiationMessage msg = GsonUtils.getGson().fromJson(json, InitiationMessage.class);
		return msg;
	}

	public static InitiationMessage extractInitiationMessage(String jsonMessage) {
		InitiationMessage msg = GsonUtils.getGson().fromJson(jsonMessage, InitiationMessage.class);
		return msg;
	}

	public static Message extractMessage(byte[] message) {
		String json = ConvertionUtils.toString(message);
		return extractMessage(json);
	}

	public static Message extractMessage(String jsonMessage) {
		Message msg = GsonUtils.getGson().fromJson(jsonMessage, Message.class);
		return msg;
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
		result = prime * result + ((expirationDate == null) ? 0 : expirationDate.hashCode());
		if (pfsSession != null) {
			result = prime * result + Arrays.hashCode(getIdentifier());
		}
		return result;
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
		SecureSession other = (SecureSession) obj;
		if (expirationDate == null) {
			if (other.expirationDate != null) {
				return false;
			}
		} else if (!expirationDate.equals(other.expirationDate)) {
			return false;
		}
		if (pfsSession == null) {
			if (other.pfsSession != null) {
				return false;
			}
		} else {
			if (!Arrays.equals(getIdentifier(), other.getIdentifier()))
				return false;
			if (!Arrays.equals(getAdditionalData(), other.getAdditionalData()))
				return false;
			if (!Arrays.equals(getDecryptionKey(), other.getDecryptionKey()))
				return false;
			if (!Arrays.equals(getEncryptionKey(), other.getEncryptionKey()))
				return false;
		}
		return true;
	}

	/**
	 * @return the pfs
	 */
	public VirgilPFS getPfs() {
		return pfs;
	}

	/**
	 * @return the expirationDate
	 */
	public Date getExpirationDate() {
		return expirationDate;
	}

	public byte[] getIdentifier() {
		return this.pfsSession.getIdentifier();
	}

	public byte[] getEncryptionKey() {
		return this.pfsSession.getEncryptionSecretKey();
	}

	public byte[] getDecryptionKey() {
		return this.pfsSession.getDecryptionSecretKey();
	}

	public byte[] getAdditionalData() {
		return this.pfsSession.getAdditionalData();
	}

}
