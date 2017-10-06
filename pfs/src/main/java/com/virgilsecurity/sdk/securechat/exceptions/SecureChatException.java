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
package com.virgilsecurity.sdk.securechat.exceptions;

import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;

public class SecureChatException extends VirgilException {

	private static final long serialVersionUID = 6892015851073423346L;

	private int code;

	/**
	 * Create new instance of {@link SecureChatException}.
	 */
	public SecureChatException() {
		super();
	}

	/**
	 * Create new instance of {@link SecureChatException}.
	 * 
	 * @param code
	 *            the error code.
	 */
	public SecureChatException(int code) {
		super();
		this.code = code;
	}

	/**
	 * Create new instance of {@link SecureChatException}.
	 * 
	 * @param code
	 *            the error code.
	 * @param message
	 *            the message.
	 */
	public SecureChatException(int code, String message) {
		super(message);
		this.code = code;
	}

	/**
	 * Create new instance of {@link SecureChatException}.
	 * 
	 * @param code
	 *            the error code.
	 * @param message
	 *            the message.
	 * @param cause
	 *            the cause.
	 */
	public SecureChatException(int code, String message, Throwable cause) {
		super(message, cause);
		this.code = code;
	}

	/**
	 * Create new instance of {@link SecureChatException}.
	 * 
	 * @param message
	 *            the message.
	 */
	public SecureChatException(String message) {
		super(message);
	}

	/**
	 * Create new instance of {@link SecureChatException}.
	 * 
	 * @param message
	 *            the message.
	 * @param cause
	 *            the cause.
	 */
	public SecureChatException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Create new instance of {@link SecureChatException}.
	 * 
	 * @param cause
	 *            the cause.
	 */
	public SecureChatException(Throwable cause) {
		super(cause);
	}

	/**
	 * Get error code.
	 * 
	 * @return the error code.
	 */
	public int getCode() {
		return code;
	}

}
