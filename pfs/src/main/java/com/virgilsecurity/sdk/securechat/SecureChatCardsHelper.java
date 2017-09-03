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
import java.util.List;

import com.virgilsecurity.sdk.client.RequestSigner;
import com.virgilsecurity.sdk.client.exceptions.VirgilClientException;
import com.virgilsecurity.sdk.client.model.CardInfoModel;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.model.dto.PublishCardSnapshotModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.device.DeviceManager;
import com.virgilsecurity.sdk.pfs.VirgilPFSClient;
import com.virgilsecurity.sdk.pfs.model.request.CreateEphemeralCardRequest;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChatCardsHelper {

    private Crypto crypto;
    private PrivateKey myPrivateKey;
    private VirgilPFSClient client;
    private DeviceManager deviceManager;
    private SecureChatKeyHelper keyHelper;

    /**
     * Create new instance of {@link SecureChatCardsHelper}.
     * 
     * @param crypto
     * @param myPrivateKey
     * @param client
     * @param deviceManager
     * @param keyHelper
     */
    public SecureChatCardsHelper(Crypto crypto, PrivateKey myPrivateKey, VirgilPFSClient client,
            DeviceManager deviceManager, SecureChatKeyHelper keyHelper) {
        super();
        this.crypto = crypto;
        this.myPrivateKey = myPrivateKey;
        this.client = client;
        this.deviceManager = deviceManager;
        this.keyHelper = keyHelper;
    }

    private CreateEphemeralCardRequest generateRequest(CardModel identityCard, KeyPair keyPair, boolean isLtc) {
        PublishCardSnapshotModel model = identityCard.getSnapshotModel();
        String identity = model.getIdentity();
        String identityType = model.getIdentityType();
        String device = this.deviceManager.getDeviceModel();
        String deviceName = this.deviceManager.getDeviceName();

        byte[] publicKeyData = this.crypto.exportPublicKey(keyPair.getPublicKey());
        CardInfoModel infoModel = new CardInfoModel();
        infoModel.setDevice(device);
        infoModel.setDeviceName(deviceName);
        CreateEphemeralCardRequest request = new CreateEphemeralCardRequest(identity, identityType, publicKeyData,
                infoModel);

        RequestSigner requestSigner = new RequestSigner(this.crypto);
        requestSigner.authoritySign(request, identityCard.getId(), this.myPrivateKey);

        return request;
    }

    public void addCards(CardModel identityCard, boolean includeLtcCard, int numberOfOtcCards) throws VirgilClientException {
        RequestSigner requestSigner = new RequestSigner(this.crypto);

        // Generate OT cards
        List<SecureChatKeyHelper.KeyEntry> otcKeys = new ArrayList<>(numberOfOtcCards);
        List<CreateEphemeralCardRequest> otcCardsRequests = new ArrayList<>(numberOfOtcCards);
        for (int i = 0; i < numberOfOtcCards; i++) {
            KeyPair keyPair = this.crypto.generateKeys();
            CreateEphemeralCardRequest request = this.generateRequest(identityCard, keyPair, false);
            String cardId = requestSigner.getCardId(request);

            otcCardsRequests.add(request);

            SecureChatKeyHelper.KeyEntry keyEntry = new SecureChatKeyHelper.KeyEntry(keyPair.getPrivateKey(), cardId);
            otcKeys.add(keyEntry);
        }

        // Generate LT cards
        SecureChatKeyHelper.KeyEntry ltcKey = null;
        CreateEphemeralCardRequest ltcCardRequest = null;
        if (includeLtcCard) {
            KeyPair keyPair = this.crypto.generateKeys();
            CreateEphemeralCardRequest request = this.generateRequest(identityCard, keyPair, true);
            String cardId = requestSigner.getCardId(request);

            ltcCardRequest = request;
            ltcKey = new SecureChatKeyHelper.KeyEntry(keyPair.getPrivateKey(), cardId);
        }

        this.keyHelper.persistKeys(otcKeys, ltcKey);

        if (ltcCardRequest != null) {
            this.client.bootstrapCardsSet(identityCard.getId(), ltcCardRequest, otcCardsRequests);
        } else if (!otcCardsRequests.isEmpty()) {
            this.client.createOneTimeCards(identityCard.getId(), otcCardsRequests);
        }
    }

}
