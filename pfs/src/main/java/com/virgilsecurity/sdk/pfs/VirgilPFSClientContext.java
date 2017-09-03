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

import java.net.MalformedURLException;
import java.net.URL;

import com.virgilsecurity.sdk.client.VirgilClientContext;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilPFSClientContext extends VirgilClientContext {

    private URL ephemeralServiceURL;

    /**
     * Create new instance of {@link VirgilPFSClientContext}.
     */
    public VirgilPFSClientContext() {
        super();
        init();
    }

    /**
     * Create new instance of {@link VirgilPFSClientContext}.
     * 
     * @param accessToken
     */
    public VirgilPFSClientContext(String accessToken) {
        super(accessToken);
        init();
    }

    private void init() {
        try {
            this.ephemeralServiceURL = new URL("https://pfs.virgilsecurity.com");
        } catch (MalformedURLException e) {
            // This should never happen
        }
    }

    /**
     * @return the ephemeralServiceURL
     */
    public URL getEphemeralServiceURL() {
        return ephemeralServiceURL;
    }

    /**
     * @param ephemeralServiceURL
     *            the ephemeralServiceURL to set
     */
    public void setEphemeralServiceURL(URL ephemeralServiceURL) {
        this.ephemeralServiceURL = ephemeralServiceURL;
    }

}
