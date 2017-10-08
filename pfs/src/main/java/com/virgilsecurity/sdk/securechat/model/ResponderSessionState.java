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

import java.util.Date;

import com.google.gson.annotations.SerializedName;

/**
 * @author Andrii Iakovenko
 *
 */
public class ResponderSessionState extends SessionState {

    private static final long serialVersionUID = 763291699492122767L;

    @SerializedName("eph_public_key_data")
    private byte[] ephPublicKeyData;

    @SerializedName("recipient_identity_card_id")
    private String recipientIdentityCardId;

    @SerializedName("recipient_identity_public_key")
    private byte[] recipientIdentityPublicKey;

    @SerializedName("recipient_long_term_card_id")
    private String recipientLongTermCardId;

    @SerializedName("recipient_one_time_card_id")
    private String recipientOneTimeCardId;

    public ResponderSessionState() {
    }

    public ResponderSessionState(byte[] sessionId, Date creationDate, Date expirationDate, byte[] additionalData,
            byte[] ephPublicKeyData, String recipientIdentityCardId, byte[] recipientIdentityPublicKey,
            String recipientLongTermCardId, String recipientOneTimeCardId) {
        super(sessionId, creationDate, expirationDate, additionalData);
        this.ephPublicKeyData = ephPublicKeyData;
        this.recipientIdentityCardId = recipientIdentityCardId;
        this.recipientIdentityPublicKey = recipientIdentityPublicKey;
        this.recipientLongTermCardId = recipientLongTermCardId;
        this.recipientOneTimeCardId = recipientOneTimeCardId;
    }

    /**
     * @return the ephPublicKeyData
     */
    public byte[] getEphPublicKeyData() {
        return ephPublicKeyData;
    }

    /**
     * @return the recipientIdentityCardId
     */
    public String getRecipientIdentityCardId() {
        return recipientIdentityCardId;
    }

    /**
     * @return the recipientIdentityPublicKey
     */
    public byte[] getRecipientIdentityPublicKey() {
        return recipientIdentityPublicKey;
    }

    /**
     * @return the recipientLongTermCardId
     */
    public String getRecipientLongTermCardId() {
        return recipientLongTermCardId;
    }

    /**
     * @return the recipientOneTimeCardId
     */
    public String getRecipientOneTimeCardId() {
        return recipientOneTimeCardId;
    }

    /**
     * @param ephPublicKeyData
     *            the ephPublicKeyData to set
     */
    public void setEphPublicKeyData(byte[] ephPublicKeyData) {
        this.ephPublicKeyData = ephPublicKeyData;
    }

    /**
     * @param recipientIdentityCardId
     *            the recipientIdentityCardId to set
     */
    public void setRecipientIdentityCardId(String recipientIdentityCardId) {
        this.recipientIdentityCardId = recipientIdentityCardId;
    }

    /**
     * @param recipientIdentityPublicKey
     *            the recipientIdentityPublicKey to set
     */
    public void setRecipientIdentityPublicKey(byte[] recipientIdentityPublicKey) {
        this.recipientIdentityPublicKey = recipientIdentityPublicKey;
    }

    /**
     * @param recipientLongTermCardId
     *            the recipientLongTermCardId to set
     */
    public void setRecipientLongTermCardId(String recipientLongTermCardId) {
        this.recipientLongTermCardId = recipientLongTermCardId;
    }

    /**
     * @param recipientOneTimeCardId
     *            the recipientOneTimeCardId to set
     */
    public void setRecipientOneTimeCardId(String recipientOneTimeCardId) {
        this.recipientOneTimeCardId = recipientOneTimeCardId;
    }

}
