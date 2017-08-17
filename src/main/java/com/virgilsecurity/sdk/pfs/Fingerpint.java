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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.virgilsecurity.crypto.VirgilHash;
import com.virgilsecurity.crypto.VirgilHash.Algorithm;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class Fingerpint {

    private static final int ITERATIONS = 4096;

    /**
     * Calculate fingerprint for card identifiers.
     * 
     * @param cardsIds
     *            the card identifiers.
     * @return the fingerprint as a string.
     */
    public static String calculateFingerprint(List<String> cardsIds) {
        List<String> sortedCardsIds = new ArrayList<>();
        if (cardsIds != null) {
            sortedCardsIds.addAll(cardsIds);
        }
        Collections.sort(sortedCardsIds);

        byte[] cardsData = null;
        try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            for (String cardId : sortedCardsIds) {
                os.write(ConvertionUtils.toBytes(cardId));
            }
            cardsData = os.toByteArray();
        } catch (IOException e) {
            // Nothing to do
        }

        byte[] previousHash = null;
        try (VirgilHash hash = new VirgilHash(Algorithm.SHA384)) {
            for (int i = 0; i < ITERATIONS; i++) {
                if (previousHash == null) {
                    previousHash = hash.hash(cardsData);
                } else {
                    byte[] data = new byte[cardsData.length + previousHash.length];
                    System.arraycopy(cardsData, 0, data, 0, cardsData.length);
                    System.arraycopy(previousHash, 0, data, cardsData.length, previousHash.length);

                    previousHash = hash.hash(data);
                }
            }
        }

        return hashToStr(previousHash);
    }

    private static String hashToStr(byte[] hash) {
        if (hash == null) {
            throw new NullArgumentException("hash");
        }
        if (hash.length != 48) {
            throw new IllegalArgumentException("Invalid hash length.");
        }

        StringBuilder res = new StringBuilder();
        for (int index = 0; index < hash.length; index += 4) {
            int endIndex = index + 4;

            ByteBuffer buffer = ByteBuffer.wrap(Arrays.copyOfRange(hash, index, endIndex));
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            long num = buffer.getInt() & 0x00000000ffffffffL;
            num = num % 100000;
            res.append(String.format("%05d ", num));
        }

        return res.substring(0, res.length() - 1);
    }

}
