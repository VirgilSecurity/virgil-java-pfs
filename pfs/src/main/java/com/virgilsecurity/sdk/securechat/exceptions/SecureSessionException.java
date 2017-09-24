package com.virgilsecurity.sdk.securechat.exceptions;

public class SecureSessionException extends SecureChatException {

	private static final long serialVersionUID = 7861067940843021678L;

	/**
	 * @param message
	 */
	public SecureSessionException(String message) {
		super(message);
	}

	/**
	 * @param code
	 * @param message
	 */
	public SecureSessionException(int code, String message) {
		super(code, message);
	}

	/**
	 * @param code
	 * @param message
	 * @param cause
	 */
	public SecureSessionException(int code, String message, Throwable cause) {
		super(code, message, cause);
	}

}
