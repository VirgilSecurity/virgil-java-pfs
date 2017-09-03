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

import com.google.gson.annotations.SerializedName;

/**
 * @author Andrii Iakovenko
 *
 */
public class InitiationMessage {

    @SerializedName("initiator_ic_id")
    private String initiatorIcId;

    @SerializedName("responder_ic_id")
    private String responderIcId;

    @SerializedName("responder_ltc_id")
    private String responderLtcId;

    @SerializedName("responder_otc_id")
    private String responderOtcId;

    @SerializedName("eph")
    private byte[] ephPublicKey;

    @SerializedName("sign")
    private byte[] ephPublicKeySignature;

    @SerializedName("salt")
    private byte[] salt;

    @SerializedName("ciphertext")
    private byte[] cipherText;
    
    

    /**
     * Create new instance of {@link InitiationMessage}.
     * @param initiatorIcId
     * @param responderIcId
     * @param responderLtcId
     * @param responderOtcId
     * @param ephPublicKey
     * @param ephPublicKeySignature
     * @param salt
     * @param cipherText
     */
    public InitiationMessage(String initiatorIcId, String responderIcId, String responderLtcId, String responderOtcId,
            byte[] ephPublicKey, byte[] ephPublicKeySignature, byte[] salt, byte[] cipherText) {
        super();
        this.initiatorIcId = initiatorIcId;
        this.responderIcId = responderIcId;
        this.responderLtcId = responderLtcId;
        this.responderOtcId = responderOtcId;
        this.ephPublicKey = ephPublicKey;
        this.ephPublicKeySignature = ephPublicKeySignature;
        this.salt = salt;
        this.cipherText = cipherText;
    }

    /**
     * @return the initiatorIcId
     */
    public String getInitiatorIcId() {
        return initiatorIcId;
    }

    /**
     * @param initiatorIcId
     *            the initiatorIcId to set
     */
    public void setInitiatorIcId(String initiatorIcId) {
        this.initiatorIcId = initiatorIcId;
    }

    /**
     * @return the responderIcId
     */
    public String getResponderIcId() {
        return responderIcId;
    }

    /**
     * @param responderIcId
     *            the responderIcId to set
     */
    public void setResponderIcId(String responderIcId) {
        this.responderIcId = responderIcId;
    }

    /**
     * @return the responderLtcId
     */
    public String getResponderLtcId() {
        return responderLtcId;
    }

    /**
     * @param responderLtcId
     *            the responderLtcId to set
     */
    public void setResponderLtcId(String responderLtcId) {
        this.responderLtcId = responderLtcId;
    }

    /**
     * @return the responderOtcId
     */
    public String getResponderOtcId() {
        return responderOtcId;
    }

    /**
     * @param responderOtcId
     *            the responderOtcId to set
     */
    public void setResponderOtcId(String responderOtcId) {
        this.responderOtcId = responderOtcId;
    }

    /**
     * @return the ephPublicKey
     */
    public byte[] getEphPublicKey() {
        return ephPublicKey;
    }

    /**
     * @param ephPublicKey
     *            the ephPublicKey to set
     */
    public void setEphPublicKey(byte[] ephPublicKey) {
        this.ephPublicKey = ephPublicKey;
    }

    /**
     * @return the ephPublicKeySignature
     */
    public byte[] getEphPublicKeySignature() {
        return ephPublicKeySignature;
    }

    /**
     * @param ephPublicKeySignature
     *            the ephPublicKeySignature to set
     */
    public void setEphPublicKeySignature(byte[] ephPublicKeySignature) {
        this.ephPublicKeySignature = ephPublicKeySignature;
    }

    /**
     * @return the salt
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * @param salt
     *            the salt to set
     */
    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    /**
     * @return the cipherText
     */
    public byte[] getCipherText() {
        return cipherText;
    }

    /**
     * @param cipherText
     *            the cipherText to set
     */
    public void setCipherText(byte[] cipherText) {
        this.cipherText = cipherText;
    }

}
