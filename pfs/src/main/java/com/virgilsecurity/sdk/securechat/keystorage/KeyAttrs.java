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
package com.virgilsecurity.sdk.securechat.keystorage;

import java.util.Date;

/**
 * This class represents attributes of keys stored in key storage.
 * 
 * @author Andrii Iakovenko
 *
 */
public class KeyAttrs {

	// Key name
	private String name;

	// Key creation date
	private Date creationDate;

	/**
	 * Create new instance of {@link KeyAttrs}.
	 */
	public KeyAttrs() {
		super();
	}

	/**
	 * Create new instance of {@link KeyAttrs}.
	 * 
	 * @param name
	 *            the key name.
	 * @param creationDate
	 *            the key createion date.
	 */
	public KeyAttrs(String name, Date creationDate) {
		super();
		this.name = name;
		this.creationDate = creationDate;
	}

	/**
	 * @return the key creation date.
	 */
	public Date getCreationDate() {
		return creationDate;
	}

	/**
	 * @return the key name.
	 */
	public String getName() {
		return name;
	}

	/**
	 * @param creationDate
	 *            the key creation date to set.
	 */
	public void setCreationDate(Date creationDate) {
		this.creationDate = creationDate;
	}

	/**
	 * @param name
	 *            the key name to set.
	 */
	public void setName(String name) {
		this.name = name;
	}

}
