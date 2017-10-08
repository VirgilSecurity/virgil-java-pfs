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
public class InitiatorSessionState extends SessionState {

    private static final long serialVersionUID = 1579806110665130516L;

    /**
     * @return the serialversionuid
     */
    public static long getSerialversionuid() {
        return serialVersionUID;
    }

    @SerializedName("eph_key_name")
    private String ephKeyName;

    @SerializedName("recipient_card_id")
    private String recipientCardId;

    @SerializedName("recipient_public_key")
    private byte[] recipientPublicKey;

    @SerializedName("recipient_long_term_card_id")
    private String recipientLongTermCardId;

    @SerializedName("recipient_long_term_public_key")
    private byte[] recipientLongTermPublicKey;

    @SerializedName("recipient_one_time_card_id")
    private String recipientOneTimeCardId;
    
    @SerializedName("recipient_one_time_public_key")
    private byte[] recipientOneTimePublicKey;

    public InitiatorSessionState() {
    }

    public InitiatorSessionState(byte[] sessionId, Date creationDate, Date expirationDate, 
            byte[] additionalData, String ephKeyName, String recipientCardId, 
            byte[] recipientPublicKey, String recipientLongTermCardId,
            byte[] recipientLongTermPublicKey, String recipientOneTimeCardId, byte[] recipientOneTimePublicKey) {
        super(sessionId, creationDate, expirationDate, additionalData);
        this.ephKeyName = ephKeyName;
        this.recipientCardId = recipientCardId;
        this.recipientPublicKey = recipientPublicKey;
        this.recipientLongTermCardId = recipientLongTermCardId;
        this.recipientLongTermPublicKey = recipientLongTermPublicKey;
        this.recipientOneTimeCardId = recipientOneTimeCardId;
        this.recipientOneTimePublicKey = recipientOneTimePublicKey;
    }

    /**
     * @return the ephKeyName
     */
    public String getEphKeyName() {
        return ephKeyName;
    }

    /**
     * @return the recipientCardId
     */
    public String getRecipientCardId() {
        return recipientCardId;
    }

    /**
     * @return the recipientLongTermCardId
     */
    public String getRecipientLongTermCardId() {
        return recipientLongTermCardId;
    }

    /**
     * @return the recipientLongTermPublicKey
     */
    public byte[] getRecipientLongTermPublicKey() {
        return recipientLongTermPublicKey;
    }

    /**
     * @return the recipientOneTimeCardId
     */
    public String getRecipientOneTimeCardId() {
        return recipientOneTimeCardId;
    }

    /**
     * @return the recipientOneTimePublicKey
     */
    public byte[] getRecipientOneTimePublicKey() {
        return recipientOneTimePublicKey;
    }

    /**
     * @return the recipientPublicKey
     */
    public byte[] getRecipientPublicKey() {
        return recipientPublicKey;
    }

    /**
     * @param ephKeyName
     *            the ephKeyName to set
     */
    public void setEphKeyName(String ephKeyName) {
        this.ephKeyName = ephKeyName;
    }

    /**
     * @param recipientCardId
     *            the recipientCardId to set
     */
    public void setRecipientCardId(String recipientCardId) {
        this.recipientCardId = recipientCardId;
    }

    /**
     * @param recipientLongTermCardId
     *            the recipientLongTermCardId to set
     */
    public void setRecipientLongTermCardId(String recipientLongTermCardId) {
        this.recipientLongTermCardId = recipientLongTermCardId;
    }

    /**
     * @param recipientLongTermPublicKey
     *            the recipientLongTermPublicKey to set
     */
    public void setRecipientLongTermPublicKey(byte[] recipientLongTermPublicKey) {
        this.recipientLongTermPublicKey = recipientLongTermPublicKey;
    }

    /**
     * @param recipientOneTimeCardId
     *            the recipientOneTimeCardId to set
     */
    public void setRecipientOneTimeCardId(String recipientOneTimeCardId) {
        this.recipientOneTimeCardId = recipientOneTimeCardId;
    }

    /**
     * @param recipientOneTimePublicKey
     *            the recipientOneTimePublicKey to set
     */
    public void setRecipientOneTimePublicKey(byte[] recipientOneTimePublicKey) {
        this.recipientOneTimePublicKey = recipientOneTimePublicKey;
    }

    /**
     * @param recipientPublicKey
     *            the recipientPublicKey to set
     */
    public void setRecipientPublicKey(byte[] recipientPublicKey) {
        this.recipientPublicKey = recipientPublicKey;
    }

}
