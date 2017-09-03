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
package com.virgilsecurity.sdk.securechat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.virgilsecurity.sdk.client.exceptions.VirgilClientException;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.securechat.model.ServiceInfoEntry;
import com.virgilsecurity.sdk.securechat.utils.GsonUtils;
import com.virgilsecurity.sdk.storage.KeyStorage;
import com.virgilsecurity.sdk.storage.VirgilKeyEntry;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChatKeyHelper {

    public static class KeyEntry {

        private String keyName;

        private PrivateKey privateKey;

        /**
         * Create new instance of {@link KeyEntry}.
         * 
         * @param privateKey
         * @param keyName
         */
        public KeyEntry(PrivateKey privateKey, String keyName) {
            super();
            this.keyName = keyName;
            this.privateKey = privateKey;
        }

        /**
         * @return the keyName
         */
        public String getKeyName() {
            return keyName;
        }

        /**
         * @return the privateKey
         */
        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        /**
         * @param keyName
         *            the keyName to set
         */
        public void setKeyName(String keyName) {
            this.keyName = keyName;
        }

        /**
         * @param privateKey
         *            the privateKey to set
         */
        public void setPrivateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
        }

    }

    private static final String SERVICE_KEY_NAME = "VIRGIL.SERVICE.INFO.%s";
    private Crypto crypto;
    private KeyStorage keyStorage;
    private String identityCardId;

    private int longTermKeyTtl;

    /**
     * Create new instance of {@link SecureChatKeyHelper}.
     * 
     * @param crypto
     * @param keyStorage
     * @param identityCardId
     * @param longTermKeyTtl
     */
    public SecureChatKeyHelper(Crypto crypto, KeyStorage keyStorage, String identityCardId, int longTermKeyTtl) {
        super();
        this.crypto = crypto;
        this.keyStorage = keyStorage;
        this.identityCardId = identityCardId;
        this.longTermKeyTtl = longTermKeyTtl;
    }

    public void gentleReset() {
        synchronized (this) {
            ServiceInfoEntry serviceInfoEntry = this.getServiceInfoEntry();
            if (serviceInfoEntry == null) {
                return;
            }
            List<String> keyEntryNames = new LinkedList<>();
            for (ServiceInfoEntry.KeyEntry keyEntry : serviceInfoEntry.getLtcKeys()) {
                keyEntryNames.add(keyEntry.getKeyName());
            }
            keyEntryNames.addAll(serviceInfoEntry.getOtcKeysNames());
            keyEntryNames.addAll(serviceInfoEntry.getEphKeysNames());
            for (String keyEntryName : keyEntryNames) {
                this.removePrivateKey(keyEntryName);
            }
            this.keyStorage.delete(this.getServiceInfoName());
        }
    }

    public List<String> getAllOtCardsIds() {
        ServiceInfoEntry serviceInfo = this.getServiceInfoEntry();

        if (serviceInfo == null) {
            return new ArrayList<>();
        }

        List<String> result = new ArrayList<>();
        for (String otcKeyName : serviceInfo.getOtcKeysNames()) {
            result.add(this.extractCardId(otcKeyName));
        }
        return result;
    }

    public PrivateKey getEphPrivateKey(String name) throws CryptoException {
        String keyName = this.getEphPrivateKeyName(name);
        return this.getPrivateKey(keyName);
    }

    public PrivateKey getEphPrivateKeyByEntryName(String keyEntryName) throws CryptoException {
        return this.getPrivateKeyByEntryName(keyEntryName);
    }

    public PrivateKey getLtPrivateKey(String name) throws CryptoException {
        String keyName = this.getLtPrivateKeyName(name);
        return this.getPrivateKey(keyName);
    }

    public PrivateKey getOtPrivateKey(String name) throws CryptoException {
        String keyName = this.getOtPrivateKeyName(name);
        return this.getPrivateKey(keyName);
    }

    public boolean hasRelevantLtKey() {
        ServiceInfoEntry serviceInfoEntry = this.getServiceInfoEntry();
        if (serviceInfoEntry == null) {
            return false;
        }

        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.SECOND, -this.longTermKeyTtl);
        Date date = cal.getTime();
        for (ServiceInfoEntry.KeyEntry ltcKey : serviceInfoEntry.getLtcKeys()) {
            if (date.before(ltcKey.getDate())) {
                return true;
            }
        }
        return false;
    }

    public String persistEphPrivateKey(PrivateKey key, String name) {
        String ephKeyEntryName = this.saveEphPrivateKey(key, name);

        synchronized (this) {
            ServiceInfoEntry serviceInfo = this.getServiceInfoEntry();
            if (serviceInfo != null) {
                List<String> keyNames = new ArrayList<>(serviceInfo.getEphKeysNames());
                keyNames.add(ephKeyEntryName);
                serviceInfo = new ServiceInfoEntry(serviceInfo.getLtcKeys(), serviceInfo.getOtcKeysNames(), keyNames);
            } else {
                serviceInfo = new ServiceInfoEntry(
                        new ArrayList<com.virgilsecurity.sdk.securechat.model.ServiceInfoEntry.KeyEntry>(),
                        new ArrayList<String>(), Arrays.asList(ephKeyEntryName));
            }
            this.updateServiceInfoEntry(serviceInfo);
        }

        return ephKeyEntryName;
    }

    public void persistKeys(List<KeyEntry> keys, KeyEntry ltKey) throws VirgilClientException {
        List<String> keyEntryNames = new ArrayList<>(keys.size());
        for (KeyEntry key : keys) {
            keyEntryNames.add(this.saveOtPrivateKey(key.privateKey, key.keyName));
        }

        String ltcKeyEntryName = null;
        if (ltKey != null) {
            ltcKeyEntryName = this.saveLtPrivateKey(ltKey.privateKey, ltKey.keyName);
        }

        ServiceInfoEntry newServiceInfo;
        ServiceInfoEntry serviceInfo = this.getServiceInfoEntry();
        if (serviceInfo != null) {
            List<ServiceInfoEntry.KeyEntry> ltcEntryArray = new ArrayList<>();
            if (ltcKeyEntryName != null) {
                ServiceInfoEntry.KeyEntry entry = new ServiceInfoEntry.KeyEntry(ltcKeyEntryName, new Date());
                ltcEntryArray.add(entry);
            }
            ltcEntryArray.addAll(serviceInfo.getLtcKeys());
            keyEntryNames.addAll(serviceInfo.getOtcKeysNames());
            newServiceInfo = new ServiceInfoEntry(ltcEntryArray, keyEntryNames, serviceInfo.getEphKeysNames());
        } else if (ltcKeyEntryName != null) {
            newServiceInfo = new ServiceInfoEntry(
                    Arrays.asList(new ServiceInfoEntry.KeyEntry(ltcKeyEntryName, new Date())), keyEntryNames,
                    new ArrayList<String>());
        } else {
            throw new VirgilClientException("LT key not found and new key was not specified.");
        }

        this.updateServiceInfoEntry(newServiceInfo);
    }

    public void removeOldKeys(Set<String> relevantEphKeys, Set<String> relevantLtCards, Set<String> relevantOtCards)
            throws VirgilClientException {
        synchronized (this) {
            ServiceInfoEntry serviceInfoEntry = this.getServiceInfoEntry();

            if (serviceInfoEntry == null) {
                if ((!relevantEphKeys.isEmpty()) || (!relevantLtCards.isEmpty()) || (!relevantOtCards.isEmpty())) {
                    throw new VirgilClientException("Trying to remove keys, but no service entry was found.");
                }
                return;
            }

            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.SECOND, -this.longTermKeyTtl);
            Date date = cal.getTime();
            Set<String> outdatedLtKeysNames = new HashSet<String>();
            for (ServiceInfoEntry.KeyEntry ltcKey : serviceInfoEntry.getLtcKeys()) {
                if (date.after(ltcKey.getDate())) {
                    outdatedLtKeysNames.add(ltcKey.getKeyName());
                }
            }

            Set<String> ltKeysToRemove = new HashSet<>(outdatedLtKeysNames);
            for (String relevantLtCard : relevantLtCards) {
                ltKeysToRemove.remove(this.getPrivateKeyEntryName(this.getLtPrivateKeyName(relevantLtCard)));
            }

            Set<String> otKeysToRemove = new HashSet<>(serviceInfoEntry.getOtcKeysNames());
            for (String relevantOtCard : relevantOtCards) {
                otKeysToRemove.remove(this.getPrivateKeyEntryName(this.getOtPrivateKeyName(relevantOtCard)));
            }

            Set<String> ephKeysToRemove = new HashSet<>(serviceInfoEntry.getEphKeysNames());
            ephKeysToRemove.removeAll(relevantEphKeys);

            Set<String> allKeysToRemove = new HashSet<>();
            allKeysToRemove.addAll(ltKeysToRemove);
            allKeysToRemove.addAll(otKeysToRemove);
            allKeysToRemove.addAll(ephKeysToRemove);

            for (String keyName : allKeysToRemove) {
                this.removePrivateKey(keyName);
            }

            // Update service info entry
            List<ServiceInfoEntry.KeyEntry> newLtcKeys = filterEntries(serviceInfoEntry.getLtcKeys(), ltKeysToRemove);
            List<String> newOtcKeyNames = filter(serviceInfoEntry.getOtcKeysNames(), otKeysToRemove);
            List<String> newEphKeyNames = filter(serviceInfoEntry.getEphKeysNames(), ephKeysToRemove);

            ServiceInfoEntry newServiceInfoEntry = new ServiceInfoEntry(newLtcKeys, newOtcKeyNames, newEphKeyNames);

            this.updateServiceInfoEntry(newServiceInfoEntry);
        }
    }

    private String extractCardId(String otKeyEntryName) {
        return otKeyEntryName.replace(this.getPrivateKeyEntryHeader() + this.getOtPrivateKeyNameHeader(), "");
    }

    private String getEphPrivateKeyName(String name) {
        return String.format("EPH_KEY.%s", name);
    }

    private String getLtPrivateKeyName(String name) {
        return String.format("LT_KEY.%s", name);
    }

    private String getOtPrivateKeyName(String name) {
        return String.format("%s%s", this.getOtPrivateKeyNameHeader(), name);
    }

    private String getPrivateKeyEntryHeader() {
        return String.format("VIRGIL.OWNER.%s.", this.identityCardId);
    }

    private String getOtPrivateKeyNameHeader() {
        return "OT_KEY.";
    }

    private PrivateKey getPrivateKey(String keyName) throws CryptoException {
        String keyEntryName = this.getPrivateKeyEntryName(keyName);

        return this.getPrivateKeyByEntryName(keyEntryName);
    }

    private PrivateKey getPrivateKeyByEntryName(String keyEntryName) throws CryptoException {
        com.virgilsecurity.sdk.storage.KeyEntry keyEntry = this.keyStorage.load(keyEntryName);

        PrivateKey privateKey = this.crypto.importPrivateKey(keyEntry.getValue());

        return privateKey;
    }

    private String getPrivateKeyEntryName(String name) {
        return String.format("%s%s", this.getPrivateKeyEntryHeader(), name);
    }

    private ServiceInfoEntry getServiceInfoEntry() {

        com.virgilsecurity.sdk.storage.KeyEntry keyEntry = null;
        try {
            keyEntry = this.keyStorage.load(this.getServiceInfoName());
        } catch (KeyEntryNotFoundException e) {
            return null;
        }
        String json = ConvertionUtils.toString(keyEntry.getValue());
        ServiceInfoEntry serviceInfoEntry = GsonUtils.getGson().fromJson(json, ServiceInfoEntry.class);

        return serviceInfoEntry;
    }

    private String getServiceInfoName() {
        return String.format(SERVICE_KEY_NAME, this.identityCardId);
    }

    private void removePrivateKey(String keyEntryName) {
        if (this.keyStorage.exists(keyEntryName)) {
            this.keyStorage.delete(keyEntryName);
        }
    }

    public void removeEphPrivateKey(String name) throws VirgilException {
        String keyEntryName = this.getPrivateKeyEntryName(this.getEphPrivateKeyName(name));
        this.removeEphPrivateKeyByEntryName(keyEntryName);
    }

    public void removeEphPrivateKeyByEntryName(String keyEntryName) throws VirgilException {
        ServiceInfoEntry serviceInfoEntry = this.getServiceInfoEntry();
        if (serviceInfoEntry == null) {
            throw new VirgilClientException("Trying to remove keys, but no service entry was found.");
        }
        this.removePrivateKey(keyEntryName);
        ServiceInfoEntry newServiceInfo = new ServiceInfoEntry(serviceInfoEntry.getLtcKeys(),
                serviceInfoEntry.getOtcKeysNames(),
                filter(serviceInfoEntry.getEphKeysNames(), Arrays.asList(keyEntryName)));
        this.updateServiceInfoEntry(newServiceInfo);
    }

    public void removeOneTimePrivateKey(String name) throws VirgilException {
        ServiceInfoEntry serviceInfoEntry = this.getServiceInfoEntry();
        if (serviceInfoEntry == null) {
            throw new VirgilClientException("Trying to remove keys, but no service entry was found.");
        }
        String keyEntryName = this.getPrivateKeyEntryName(this.getOtPrivateKeyName(name));
        this.removePrivateKey(keyEntryName);
        ServiceInfoEntry newServiceInfo = new ServiceInfoEntry(serviceInfoEntry.getLtcKeys(),
                filter(serviceInfoEntry.getOtcKeysNames(), Arrays.asList(keyEntryName)),
                serviceInfoEntry.getEphKeysNames());
        this.updateServiceInfoEntry(newServiceInfo);
    }

    public boolean isEphKeyExists(String ephName) {
        String keyEntryName = this.getPrivateKeyEntryName(this.getEphPrivateKeyName(ephName));
        return this.keyStorage.exists(keyEntryName);
    }

    public boolean isOtKeyExists(String otName) {
        String keyEntryName = this.getPrivateKeyEntryName(this.getOtPrivateKeyName(otName));
        return this.keyStorage.exists(keyEntryName);
    }

    private String saveEphPrivateKey(PrivateKey key, String name) {
        String keyName = this.getEphPrivateKeyName(name);
        return this.savePrivateKey(key, keyName);
    }

    private String saveLtPrivateKey(PrivateKey key, String name) {
        String keyName = this.getLtPrivateKeyName(name);
        return this.savePrivateKey(key, keyName);
    }

    private String saveOtPrivateKey(PrivateKey key, String name) {
        String keyName = this.getOtPrivateKeyName(name);
        return this.savePrivateKey(key, keyName);
    }

    private String savePrivateKey(PrivateKey key, String keyName) {
        byte[] privateKeyData = this.crypto.exportPrivateKey(key);

        String keyEntryName = this.getPrivateKeyEntryName(keyName);
        com.virgilsecurity.sdk.storage.KeyEntry keyEntry = new VirgilKeyEntry(keyEntryName, privateKeyData);

        this.keyStorage.store(keyEntry);

        return keyEntryName;
    }

    private void updateServiceInfoEntry(ServiceInfoEntry newEntry) {
        String entryName = this.getServiceInfoName();
        if (this.keyStorage.exists(entryName)) {
            this.keyStorage.delete(entryName);
        }

        String json = GsonUtils.getGson().toJson(newEntry);
        byte[] data = ConvertionUtils.toBytes(json);

        com.virgilsecurity.sdk.storage.KeyEntry keyEntry = new VirgilKeyEntry(entryName, data);

        this.keyStorage.store(keyEntry);
    }

    private List<ServiceInfoEntry.KeyEntry> filterEntries(Collection<ServiceInfoEntry.KeyEntry> entries,
            Collection<String> excludeNames) {
        List<ServiceInfoEntry.KeyEntry> result = new ArrayList<>();
        for (ServiceInfoEntry.KeyEntry entry : entries) {
            if (!excludeNames.contains(entry.getKeyName())) {
                result.add(entry);
            }
        }
        return result;
    }

    private List<String> filter(Collection<String> keyNames, Collection<String> excludeNames) {
        List<String> result = new ArrayList<>(keyNames);
        result.removeAll(excludeNames);
        return result;
    }

}
