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
import java.util.List;

import com.google.gson.annotations.SerializedName;

/**
 * @author Andrii Iakovenko
 *
 */
public class ServiceInfoEntry {

    @SerializedName("otc_keys_names")
    private List<String> otcKeysNames;

    @SerializedName("ltc_keys")
    private List<KeyEntry> ltcKeys;

    @SerializedName("eph_keys_names")
    private List<String> ephKeysNames;

    /**
     * Create new instance of {@link ServiceInfoEntry}.
     * @param otcKeysNames
     * @param ltcKeys
     * @param ephKeysNames
     */
    public ServiceInfoEntry(List<KeyEntry> ltcKeys, List<String> otcKeysNames, List<String> ephKeysNames) {
        super();
        this.otcKeysNames = otcKeysNames;
        this.ltcKeys = ltcKeys;
        this.ephKeysNames = ephKeysNames;
    }

    public static class KeyEntry {
        @SerializedName("key_name")
        private String keyName;

        @SerializedName("date")
        private Date date;

        /**
         * Create new instance of {@link KeyEntry}.
         */
        public KeyEntry() {
            super();
        }

        /**
         * Create new instance of {@link KeyEntry}.
         * 
         * @param keyName
         * @param date
         */
        public KeyEntry(String keyName, Date date) {
            this.keyName = keyName;
            this.date = date;
        }

        /**
         * @return the keyName
         */
        public String getKeyName() {
            return keyName;
        }

        /**
         * @param keyName
         *            the keyName to set
         */
        public void setKeyName(String keyName) {
            this.keyName = keyName;
        }

        /**
         * @return the date
         */
        public Date getDate() {
            return date;
        }

        /**
         * @param date
         *            the date to set
         */
        public void setDate(Date date) {
            this.date = date;
        }

    }

    /**
     * @return the otcKeysNames
     */
    public List<String> getOtcKeysNames() {
        return otcKeysNames;
    }

    /**
     * @param otcKeysNames
     *            the otcKeysNames to set
     */
    public void setOtcKeysNames(List<String> otcKeysNames) {
        this.otcKeysNames = otcKeysNames;
    }

    /**
     * @return the ltcKeys
     */
    public List<KeyEntry> getLtcKeys() {
        return ltcKeys;
    }

    /**
     * @param ltcKeys
     *            the ltcKeys to set
     */
    public void setLtcKeys(List<KeyEntry> ltcKeys) {
        this.ltcKeys = ltcKeys;
    }

    /**
     * @return the ephKeysNames
     */
    public List<String> getEphKeysNames() {
        return ephKeysNames;
    }

    /**
     * @param ephKeysNames
     *            the ephKeysNames to set
     */
    public void setEphKeysNames(List<String> ephKeysNames) {
        this.ephKeysNames = ephKeysNames;
    }

}
