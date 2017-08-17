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

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.virgilsecurity.sdk.client.ClientBase;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.model.dto.SignableRequestModel;
import com.virgilsecurity.sdk.pfs.exceptions.VirgilPFSServiceException;
import com.virgilsecurity.sdk.pfs.model.RecipientCardsSet;
import com.virgilsecurity.sdk.pfs.model.request.BootstrapCardsRequest;
import com.virgilsecurity.sdk.pfs.model.request.CreateEphemeralCardRequest;
import com.virgilsecurity.sdk.pfs.model.request.CredentialsRequest;
import com.virgilsecurity.sdk.pfs.model.request.ValidateOTCRequest;
import com.virgilsecurity.sdk.pfs.model.response.BootstrapCardsResponse;
import com.virgilsecurity.sdk.pfs.model.response.OtcCountResponse;
import com.virgilsecurity.sdk.pfs.model.response.ValidateOTCResponse;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilPFSClient extends ClientBase {

    /**
     * Create a new instance of {@code VirgilPFSClient}
     *
     * @param context
     *            the Virgil client context.
     */
    public VirgilPFSClient(VirgilPFSClientContext context) {
        super(context);
    }

    public BootstrapCardsResponse bootstrapCardsSet(String recipientId, CreateEphemeralCardRequest longTimeCardRequest,
            List<CreateEphemeralCardRequest> oneTimeCardRequests) throws VirgilServiceException {
        try {
            URL url = new URL(getContext().getEphemeralServiceURL(), String.format("/v1/recipient/%s", recipientId));

            List<SignableRequestModel> otcRequests = new ArrayList<>();
            for (CreateEphemeralCardRequest request : oneTimeCardRequests) {
                otcRequests.add(request.getRequestModel());
            }
            BootstrapCardsRequest requestModel = new BootstrapCardsRequest();
            requestModel.setLongTimeCard(longTimeCardRequest.getRequestModel());
            requestModel.setOneTimeCards(otcRequests);

            String body = ConvertionUtils.getGson().toJson(requestModel);

            BootstrapCardsResponse responseModel = execute(url, "PUT",
                    new ByteArrayInputStream(ConvertionUtils.toBytes(body)), BootstrapCardsResponse.class);

            return responseModel;
        } catch (VirgilServiceException e) {
            throw new VirgilPFSServiceException(e.getErrorCode(), e);
        } catch (Exception e) {
            throw new VirgilPFSServiceException(e);
        }
    }

    public CardModel createLongTermCard(String recipientId, CreateEphemeralCardRequest longTermCardRequest) {
        try {
            URL url = new URL(getContext().getEphemeralServiceURL(),
                    String.format("/v1/recipient/%s/actions/push-ltc", recipientId));

            String body = ConvertionUtils.getGson().toJson(longTermCardRequest.getRequestModel());

            CardModel responseModel = execute(url, "POST", new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                    CardModel.class);

            return responseModel;
        } catch (VirgilServiceException e) {
            throw new VirgilPFSServiceException(e.getErrorCode(), e);
        } catch (Exception e) {
            throw new VirgilPFSServiceException(e);
        }
    }

    public List<CardModel> createOneTimeCards(String recipientId,
            List<CreateEphemeralCardRequest> oneTimeCardsRequest) {
        try {
            URL url = new URL(getContext().getEphemeralServiceURL(),
                    String.format("/v1/recipient/%s/actions/push-otcs", recipientId));

            List<SignableRequestModel> request = new ArrayList<>();
            for (CreateEphemeralCardRequest oneTimeCardRequest : oneTimeCardsRequest) {
                request.add(oneTimeCardRequest.getRequestModel());
            }
            String body = ConvertionUtils.getGson().toJson(request);

            CardModel[] responseModel = execute(url, "POST", new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                    CardModel[].class);

            return Arrays.asList(responseModel);
        } catch (VirgilServiceException e) {
            throw new VirgilPFSServiceException(e.getErrorCode(), e);
        } catch (Exception e) {
            throw new VirgilPFSServiceException(e);
        }
    }

    public OtcCountResponse getOtcCount(String recipientId) {
        try {
            URL url = new URL(getContext().getEphemeralServiceURL(),
                    String.format("/v1/recipient/%s/actions/count-otcs", recipientId));

            OtcCountResponse responseModel = execute(url, "POST", null, OtcCountResponse.class);

            return responseModel;
        } catch (VirgilServiceException e) {
            throw new VirgilPFSServiceException(e.getErrorCode(), e);
        } catch (Exception e) {
            throw new VirgilPFSServiceException(e);
        }
    }

    public List<RecipientCardsSet> getRecipientCardsSet(String cardsIds) {
        return getRecipientCardsSet(Arrays.asList(cardsIds));
    }
    
    public List<RecipientCardsSet> getRecipientCardsSet(List<String> cardsIds) {
        try {
            URL url = new URL(getContext().getEphemeralServiceURL(), "/v1/recipient/actions/search-by-ids");

            String body = ConvertionUtils.getGson().toJson(new CredentialsRequest(cardsIds));

            RecipientCardsSet[] responseModel = execute(url, "POST",
                    new ByteArrayInputStream(ConvertionUtils.toBytes(body)), RecipientCardsSet[].class);

            return Arrays.asList(responseModel);
        } catch (VirgilServiceException e) {
            throw new VirgilPFSServiceException(e.getErrorCode(), e);
        } catch (Exception e) {
            throw new VirgilPFSServiceException(e);
        }
    }

    public List<String> validateOneTimeCards(String recipientId, List<String> cardsIds) {
        try {
            URL url = new URL(getContext().getEphemeralServiceURL(),
                    String.format("/v1/recipient/%s/actions/validate-otcs", recipientId));

            String body = ConvertionUtils.getGson().toJson(new ValidateOTCRequest(cardsIds));

            ValidateOTCResponse responseModel = execute(url, "POST",
                    new ByteArrayInputStream(ConvertionUtils.toBytes(body)), ValidateOTCResponse.class);

            return responseModel.getCardsIds();
        } catch (VirgilServiceException e) {
            throw new VirgilPFSServiceException(e.getErrorCode(), e);
        } catch (Exception e) {
            throw new VirgilPFSServiceException(e);
        }
    }

    private VirgilPFSClientContext getContext() {
        return (VirgilPFSClientContext) context;
    }

}
