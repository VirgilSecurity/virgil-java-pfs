package com.virgilsecurity.sdk.securechat.exceptions;

import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;

public class SecureChatException extends VirgilException {

	private static final long serialVersionUID = 6892015851073423346L;

	private int code;

	/**
	 * 
	 */
	public SecureChatException() {
		super();
	}

	/**
	 * @param code
	 */
	public SecureChatException(int code) {
		super();
		this.code = code;
	}

	/**
	 * @param message
	 * @param cause
	 */
	public SecureChatException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * @param code
	 * @param message
	 * @param cause
	 */
	public SecureChatException(int code, String message, Throwable cause) {
		super(message, cause);
		this.code = code;
	}

	/**
	 * @param message
	 */
	public SecureChatException(String message) {
		super(message);
	}

	/**
	 * @param code
	 * @param message
	 */
	public SecureChatException(int code, String message) {
		super(message);
		this.code = code;
	}

	/**
	 * @param cause
	 */
	public SecureChatException(Throwable cause) {
		super(cause);
	}

	/**
	 * @return the code
	 */
	public int getCode() {
		return code;
	}

}
