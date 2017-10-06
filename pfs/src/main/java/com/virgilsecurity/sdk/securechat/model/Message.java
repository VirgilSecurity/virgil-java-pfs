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

import java.util.Arrays;

import com.google.gson.annotations.SerializedName;

/**
 * @author Andrii Iakovenko
 *
 */
public class Message {

    @SerializedName("session_id")
    private byte[] sessionId;

    @SerializedName("salt")
    private byte[] salt;

    @SerializedName("ciphertext")
    private byte[] cipherText;

    /**
     * Create new instance of {@link Message}.
     */
    public Message() {
    }

    /**
     * Create new instance of {@link Message}.
     * 
     * @param sessionId
     * @param salt
     * @param cipherText
     */
    public Message(byte[] sessionId, byte[] salt, byte[] cipherText) {
        super();
        this.sessionId = sessionId;
        this.salt = salt;
        this.cipherText = cipherText;
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
        Message other = (Message) obj;
        if (!Arrays.equals(cipherText, other.cipherText))
            return false;
        if (!Arrays.equals(salt, other.salt))
            return false;
        if (!Arrays.equals(sessionId, other.sessionId))
            return false;
        return true;
    }

    /**
     * @return the cipherText
     */
    public byte[] getCipherText() {
        return cipherText;
    }

    /**
     * @return the salt
     */
    public byte[] getSalt() {
        return salt;
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
        result = prime * result + Arrays.hashCode(cipherText);
        result = prime * result + Arrays.hashCode(salt);
        result = prime * result + Arrays.hashCode(sessionId);
        return result;
    }

    /**
     * @param cipherText
     *            the cipherText to set
     */
    public void setCipherText(byte[] cipherText) {
        this.cipherText = cipherText;
    }

    /**
     * @param salt
     *            the salt to set
     */
    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    /**
     * @param sessionId
     *            the sessionId to set
     */
    public void setSessionId(byte[] sessionId) {
        this.sessionId = sessionId;
    }

}
