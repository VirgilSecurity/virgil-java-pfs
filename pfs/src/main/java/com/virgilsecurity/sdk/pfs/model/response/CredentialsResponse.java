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
package com.virgilsecurity.sdk.pfs.model.response;

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.client.model.CardModel;

/**
 * @author Andrii Iakovenko
 *
 */
public class CredentialsResponse {
    
    @SerializedName("identity_card")
    private CardModel identityCard;

    @SerializedName("long_time_card")
    private CardModel longTimeCard;

    @SerializedName("one_time_card")
    private CardModel oneTimeCard;

    /**
     * @return the identityCard
     */
    public CardModel getIdentityCard() {
        return identityCard;
    }

    /**
     * @return the longTimeCard
     */
    public CardModel getLongTimeCard() {
        return longTimeCard;
    }

    /**
     * @return the oneTimeCard
     */
    public CardModel getOneTimeCard() {
        return oneTimeCard;
    }

    /**
     * @param identityCard the identityCard to set
     */
    public void setIdentityCard(CardModel identityCard) {
        this.identityCard = identityCard;
    }

    /**
     * @param longTimeCard the longTimeCard to set
     */
    public void setLongTimeCard(CardModel longTimeCard) {
        this.longTimeCard = longTimeCard;
    }

    /**
     * @param oneTimeCard the oneTimeCard to set
     */
    public void setOneTimeCard(CardModel oneTimeCard) {
        this.oneTimeCard = oneTimeCard;
    }
    
    

}
