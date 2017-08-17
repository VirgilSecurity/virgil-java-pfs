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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.UUID;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.securechat.model.ServiceInfoEntry;
import com.virgilsecurity.sdk.securechat.model.ServiceInfoEntry.KeyEntry;
import com.virgilsecurity.sdk.storage.KeyStorage;
import com.virgilsecurity.sdk.storage.VirgilKeyEntry;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class SecureChatKeyHelperTest {

    private static final String IDENTITY_CARD_ID = UUID.randomUUID().toString();
    private static final int LONG_TERM_KEY_TTL = 3;

    private SecureChatKeyHelper keyHelper;
    private Crypto crypto;

    private PrivateKey privateKey;

    @Mock
    private KeyStorage keyStorage;

    @Before
    public void setUp() {
        crypto = new VirgilCrypto();
        privateKey = crypto.generateKeys().getPrivateKey();
        keyHelper = new SecureChatKeyHelper(this.crypto, this.keyStorage, IDENTITY_CARD_ID, LONG_TERM_KEY_TTL);
    }

    @Test
    public void getEphPrivateKey() throws VirgilException {
        String key = String.format("VIRGIL.OWNER.%s.EPH_KEY.EPH_PRIVATE_KEY", IDENTITY_CARD_ID);
        when(keyStorage.load(key)).thenReturn(new VirgilKeyEntry(key, privateKey.getValue()));
        PrivateKey loadedKey = keyHelper.getEphPrivateKey("EPH_PRIVATE_KEY");

        assertArrayEquals(this.privateKey.getId(), loadedKey.getId());
        verify(keyStorage, times(1)).load(key);
    }

    @Test
    public void getEphPrivateKeyByEntryName() throws VirgilException {
        when(keyStorage.load("VIRGIL.EPH_KEY.EPH_PRIVATE_KEY"))
                .thenReturn(new VirgilKeyEntry("VIRGIL.EPH_KEY.EPH_PRIVATE_KEY", privateKey.getValue()));
        PrivateKey loadedKey = keyHelper.getEphPrivateKeyByEntryName("VIRGIL.EPH_KEY.EPH_PRIVATE_KEY");

        assertArrayEquals(this.privateKey.getId(), loadedKey.getId());
        verify(keyStorage, times(1)).load("VIRGIL.EPH_KEY.EPH_PRIVATE_KEY");
    }

    @Test
    public void getLtPrivateKey() throws VirgilException {
        String key = String.format("VIRGIL.OWNER.%s.LT_KEY.LT_PRIVATE_KEY", IDENTITY_CARD_ID);
        when(keyStorage.load(key)).thenReturn(new VirgilKeyEntry(key, privateKey.getValue()));
        PrivateKey loadedKey = keyHelper.getLtPrivateKey("LT_PRIVATE_KEY");

        assertArrayEquals(this.privateKey.getId(), loadedKey.getId());
        verify(keyStorage, times(1)).load(key);
    }

    @Test
    public void getOtPrivateKey() throws VirgilException {
        String key = String.format("VIRGIL.OWNER.%s.OT_KEY.OT_PRIVATE_KEY", IDENTITY_CARD_ID);
        when(keyStorage.load(key)).thenReturn(new VirgilKeyEntry(key, privateKey.getValue()));
        PrivateKey loadedKey = keyHelper.getOtPrivateKey("OT_PRIVATE_KEY");

        assertArrayEquals(this.privateKey.getId(), loadedKey.getId());
        verify(keyStorage, times(1)).load(key);
    }

    @Test
    public void hasRelevantLtKey_noKeys() {
        List<KeyEntry> ltcKeys = new ArrayList<>();
        List<String> otcKeysNames = new ArrayList<>();
        List<String> ephKeysNames = new ArrayList<>();
        ServiceInfoEntry infoEntry = new ServiceInfoEntry(ltcKeys, otcKeysNames, ephKeysNames);

        String key = String.format("VIRGIL.SERVICE.INFO.%s", IDENTITY_CARD_ID);
        when(keyStorage.load(key)).thenReturn(
                new VirgilKeyEntry(key, ConvertionUtils.toBytes(ConvertionUtils.getGson().toJson(infoEntry))));

        assertFalse(keyHelper.hasRelevantLtKey());
    }

    @Test
    public void hasRelevantLtKey_onlyExpiredKeys() {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.HOUR, -1);
        KeyEntry keyEntry = new KeyEntry(IDENTITY_CARD_ID, cal.getTime());

        List<KeyEntry> ltcKeys = new ArrayList<>();
        ltcKeys.add(keyEntry);

        List<String> otcKeysNames = new ArrayList<>();
        List<String> ephKeysNames = new ArrayList<>();
        ServiceInfoEntry infoEntry = new ServiceInfoEntry(ltcKeys, otcKeysNames, ephKeysNames);

        String key = String.format("VIRGIL.SERVICE.INFO.%s", IDENTITY_CARD_ID);
        when(keyStorage.load(key)).thenReturn(
                new VirgilKeyEntry(key, ConvertionUtils.toBytes(ConvertionUtils.getGson().toJson(infoEntry))));

        assertFalse(keyHelper.hasRelevantLtKey());
    }

    @Test
    public void hasRelevantLtKey() {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.HOUR, 1);
        KeyEntry keyEntry = new KeyEntry(IDENTITY_CARD_ID, cal.getTime());

        List<KeyEntry> ltcKeys = new ArrayList<>();
        ltcKeys.add(keyEntry);

        List<String> otcKeysNames = new ArrayList<>();
        List<String> ephKeysNames = new ArrayList<>();
        ServiceInfoEntry infoEntry = new ServiceInfoEntry(ltcKeys, otcKeysNames, ephKeysNames);

        String key = String.format("VIRGIL.SERVICE.INFO.%s", IDENTITY_CARD_ID);
        when(keyStorage.load(key)).thenReturn(
                new VirgilKeyEntry(key, ConvertionUtils.toBytes(ConvertionUtils.getGson().toJson(infoEntry))));

        assertTrue(keyHelper.hasRelevantLtKey());
    }

    @Test
    @Ignore
    public void persistEphPrivateKey() {
    }

    @Test
    @Ignore
    public void persistKeys() {
    }

    @Test
    @Ignore
    public void removeOldKeys() {
    }

    @Test
    @Ignore
    public void getAllOtCardsIds() {
    }

}
