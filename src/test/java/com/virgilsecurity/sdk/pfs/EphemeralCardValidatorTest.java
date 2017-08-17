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
package com.virgilsecurity.sdk.pfs;

import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class EphemeralCardValidatorTest {

    private EphemeralCardValidator validator;
    private CardModel card;

    @Before
    public void setUp() {
        Crypto crypto = new VirgilCrypto();
        validator = new EphemeralCardValidator(crypto);

        card = new CardModel();
        card.getMeta().setVersion("4.0");
        card.setId("82bb6e421bf0bef7ec750aa4652e4694caab75fe17465ef4b10cd89d355ba813");
        card.setSnapshot(ConvertionUtils.base64ToBytes(
                "eyJpZGVudGl0eSI6ImFsaWNlIiwiaWRlbnRpdHlfdHlwZSI6InVzZXJuYW1lIiwicHVibGljX2tleSI6Ik1Db3dCUVlESzJWd0F5RUFCc1h5bkFFcXpwaysrV0VTQUdEYUxRZlNLKzcxYUNKU21DUGN4UjZOekVNPSIsInNjb3BlIjoiYXBwbGljYXRpb24iLCJkYXRhIjp7fX0="));
    }

    @Test
    public void validate_noValidators() {
        assertTrue(validator.validate(card));
    }
    
    @Test
    @Ignore
    public void validate_singleValidator() {
        validator.addVerifier("1ef2e45f6100792bc600828f1425b27ce7655a80543118f375bd894d7313aa00",
                ConvertionUtils.base64ToBytes("MCowBQYDK2VwAyEAMUJeUOZuodMPxg3/MrMxPVw+2+WYGrHcQ5S4NISIvSA="));
        assertTrue(validator.validate(card));
    }
}
