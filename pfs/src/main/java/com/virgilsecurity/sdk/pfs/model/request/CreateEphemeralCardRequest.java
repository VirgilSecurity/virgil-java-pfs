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
package com.virgilsecurity.sdk.pfs.model.request;

import java.util.Map;

import com.virgilsecurity.sdk.client.model.CardInfoModel;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;

/**
 * @author Andrii Iakovenko
 *
 */
public class CreateEphemeralCardRequest extends PublishCardRequest {

    /**
     * Create new instance of {@link CreateEphemeralCardRequest}.
     * 
     * @param snapshot
     * @param signatures
     */
    public CreateEphemeralCardRequest(byte[] snapshot, Map<String, byte[]> signatures) {
        super(snapshot, signatures);
    }

    /**
     * Create new instance of {@link CreateEphemeralCardRequest}.
     * 
     * @param identity
     * @param identityType
     * @param publicKeyData
     * @param info
     * @param customFields
     */
    public CreateEphemeralCardRequest(String identity, String identityType, byte[] publicKeyData, CardInfoModel info,
            Map<String, String> customFields) {
        super(identity, identityType, publicKeyData, info, customFields);
    }

    /**
     * Create new instance of {@link CreateEphemeralCardRequest}.
     * 
     * @param identity
     * @param identityType
     * @param publicKeyData
     * @param info
     */
    public CreateEphemeralCardRequest(String identity, String identityType, byte[] publicKeyData, CardInfoModel info) {
        super(identity, identityType, publicKeyData, info);
    }

    /**
     * Create new instance of {@link CreateEphemeralCardRequest}.
     * 
     * @param identity
     * @param identityType
     * @param publicKeyData
     */
    public CreateEphemeralCardRequest(String identity, String identityType, byte[] publicKeyData) {
        super(identity, identityType, publicKeyData);
    }

    /**
     * Create new instance of {@link CreateEphemeralCardRequest}.
     * 
     * @param stringifiedRequest
     */
    public CreateEphemeralCardRequest(String stringifiedRequest) {
        super(stringifiedRequest);
    }

}
