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

import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Test;

/**
 * @author Andrii Iakovenko
 *
 */
public class FingerpintTest {

	@Test
	public void calculateFingerprint() {
		assertEquals("95767 63932 18392 87777 58010 79361 43185 89666 69268 33576 75875 36436",
				Fingerpint.calculateFingerprint(Arrays.asList("b", "c", "a")));

		assertEquals("30040 86431 59747 52666 37436 94430 71043 18723 34794 81546 12838 92218",
				Fingerpint.calculateFingerprint(
						Arrays.asList("7053f3b4ac89480f3a4c43c1fdb0f09b8154236175b7f55aac9b920d10a4adc7",
								"78e75f23163ae7d9568e992b73d77c91d868dbdf91099144bb019859364f698c",
								"ebbc9ebcc76c6dd1dd4f44e66b8166e57f630d28b5052a56e651dda033f3dc9d")));
	}

	@Test
	public void calculateFingerprint_null() {
		assertEquals("77280 94838 05109 76792 79810 36961 01962 79001 88169 95517 85123 91127",
				Fingerpint.calculateFingerprint(null));
	}

	@Test
	public void calculateFingerprint_empty() {
		assertEquals("77280 94838 05109 76792 79810 36961 01962 79001 88169 95517 85123 91127",
				Fingerpint.calculateFingerprint(null));
	}

	@Test
	public void calculateFingerprint_nullValues() {
		assertEquals("95767 63932 18392 87777 58010 79361 43185 89666 69268 33576 75875 36436",
				Fingerpint.calculateFingerprint(Arrays.asList("b", "c", null, "a")));

		assertEquals("30040 86431 59747 52666 37436 94430 71043 18723 34794 81546 12838 92218",
				Fingerpint.calculateFingerprint(
						Arrays.asList("7053f3b4ac89480f3a4c43c1fdb0f09b8154236175b7f55aac9b920d10a4adc7", null,
								"78e75f23163ae7d9568e992b73d77c91d868dbdf91099144bb019859364f698c",
								"ebbc9ebcc76c6dd1dd4f44e66b8166e57f630d28b5052a56e651dda033f3dc9d", null)));
	}

}
