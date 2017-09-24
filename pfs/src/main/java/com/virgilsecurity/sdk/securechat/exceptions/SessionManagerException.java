package com.virgilsecurity.sdk.securechat.exceptions;

/**
 * @author Andrii Iakovenko
 *
 */
public class SessionManagerException extends SecureChatException {

	private static final long serialVersionUID = -4897072944967377559L;

	/**
	 * @param code
	 * @param message
	 * @param cause
	 */
	public SessionManagerException(int code, String message, Throwable cause) {
		super(code, message, cause);
	}

	/**
	 * @param code
	 * @param message
	 */
	public SessionManagerException(int code, String message) {
		super(code, message);
	}

}
