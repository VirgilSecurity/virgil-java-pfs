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
package com.virgilsecurity.sdk.pfs.model;

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.client.model.CardModel;

/**
 * @author Andrii Iakovenko
 *
 */
public class RecipientCardsSet {

	@SerializedName("identity_card")
	private CardModel identityCard;

	@SerializedName("long_time_card")
	private CardModel longTermCard;

	@SerializedName("one_time_card")
	private CardModel oneTimeCard;

	/**
	 * Create new instance of {@link RecipientCardsSet}.
	 */
	public RecipientCardsSet() {
	}

	/**
	 * Create new instance of {@link RecipientCardsSet}.
	 * 
	 * @param longTermCard
	 *            the long term card.
	 * @param oneTimeCard
	 *            the one-time card.
	 */
	public RecipientCardsSet(CardModel longTermCard, CardModel oneTimeCard) {
		super();
		this.longTermCard = longTermCard;
		this.oneTimeCard = oneTimeCard;
	}

	/**
	 * Get identity card.
	 * 
	 * @return the identity card.
	 */
	public CardModel getIdentityCard() {
		return identityCard;
	}

	/**
	 * Get the long term card.
	 * 
	 * @return the long term card.
	 */
	public CardModel getLongTermCard() {
		return longTermCard;
	}

	/**
	 * Get the one-time card.
	 * 
	 * @return one-time card.
	 */
	public CardModel getOneTimeCard() {
		return oneTimeCard;
	}

	/**
	 * Set identity card.
	 * 
	 * @param identityCard
	 *            the identity card to set
	 */
	public void setIdentityCard(CardModel identityCard) {
		this.identityCard = identityCard;
	}

	/**
	 * Set the long term card.
	 * 
	 * @param longTermCard
	 *            the long term card to set.
	 */
	public void setLongTermCard(CardModel longTermCard) {
		this.longTermCard = longTermCard;
	}

	/**
	 * Set one-time card.
	 * 
	 * @param oneTimeCard
	 *            the one-time card to set.
	 */
	public void setOneTimeCard(CardModel oneTimeCard) {
		this.oneTimeCard = oneTimeCard;
	}

}
