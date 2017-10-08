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

import java.util.UUID;

import org.apache.commons.lang.StringUtils;

import com.virgilsecurity.sdk.client.RequestSigner;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;

/**
 * @author Andrii Iakovenko
 *
 */
public class BaseIT {

	protected String APP_ID = getPropertyByName("APP_ID");
	protected String APP_BUNDLE = getPropertyByName("APP_BUNDLE");
	protected String APP_TOKEN = getPropertyByName("APP_TOKEN");
	protected String APP_PRIVATE_KEY_PASSWORD = getPropertyByName("APP_PRIVATE_KEY_PASSWORD");
	protected String APP_PRIVATE_KEY = StringUtils.replace(getPropertyByName("APP_PRIVATE_KEY"), "\\n", "\n");
	protected String EMAIL = getPropertyByName("TEST_EMAIL");
	protected String MAILINATOR_ID = getPropertyByName("MAILINATOR_ID");
	
	protected Crypto crypto;
	protected PrivateKey appKey;

	public String getPropertyByName(String propertyName) {
		if (StringUtils.isBlank(System.getProperty(propertyName))) {
			return null;
		}
		return System.getProperty(propertyName);
	}

	protected PublishCardRequest instantiateCreateCardRequest(KeyPair keyPair) {
		byte[] exportedPublicKey = crypto.exportPublicKey(keyPair.getPublicKey());
		String identity = UUID.randomUUID().toString();
		String identityType = "test_type";

		PublishCardRequest request = new PublishCardRequest(identity, identityType, exportedPublicKey);
		RequestSigner signer = new RequestSigner(crypto);
		signer.selfSign(request, keyPair.getPrivateKey());
		signer.authoritySign(request, APP_ID, appKey);

		return request;
	}

}
