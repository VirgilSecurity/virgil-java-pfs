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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.securechat.TestUtils;

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

		card = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI3KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUdYWEpDVFdpc25cL1VReUNjM0o3WUk3a1QwcEJzUlJqWFZweVlzcDN3aGRtN0p3YlljN2RTVkdSWXdtaEtWODBjSGVKVUw4S0JvNENzT2Uzb3p5RGhRaz0iLCJhNjY2MzE4MDcxMjc0YWRiNzM4YWYzZjY3YjhjN2VjMjlkOTU0ZGUyY2FiZmQ3MWE5NDJlNmVhMzhlNTlmZmY5IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUURzS3pDQ3Jxb1hlY3Q4V3psVGphRlVXTWkyeEtJYkxKa0Fnd3AyTnBnd3RuYVpoYURsSllMbGh4WDlma25EQTNSRW5nSzBYSExRaG40Zzkxa3NKSmdZPSIsImU2ODBiZWY4N2JhNzVkMzMxYjBhMDJiZmE2YTIwZjAyZWI1YzViYTliYzk2ZmM2MWNhNTk1NDA0YjEwMDI2ZjQiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRRXlobUxHOURiTHBWa3k3c2ttUTVBRTN4T21lMVlpVUpWNjFlemRSZ04rTGlwSmJrclwvclB1VXo3eFJERmUzY294TGM2elRFbUZlK1BqV1BMTnVFcGdrPSJ9fSwiY29udGVudF9zbmFwc2hvdCI6ImV5SndkV0pzYVdOZmEyVjVJam9pVFVOdmQwSlJXVVJMTWxaM1FYbEZRVlZaVTNkQk5XZE9iR2RUVXpSMVQwSlFibmRLVDNOQmFsVkJSSEk1V2xwbFdGWjROakp2YTB0V2RFMDlJaXdpYVdSbGJuUnBkSGtpT2lKQ1JqbEdORFZHUVMwMU9EbEZMVFF6TlRBdE9FVkNRUzAyUWtaRlFVTkNOa05GUTBVaUxDSnBaR1Z1ZEdsMGVWOTBlWEJsSWpvaWRHVnpkQ0lzSW5OamIzQmxJam9pWVhCd2JHbGpZWFJwYjI0aWZRPT0iLCJpZCI6IjhlMWE4NWEwNGEyZWY2MmFjMzkwZDYyYWE5YzQ3ODQ4ZjViMGM3NGNlZTliZjg2NzFkOTI5Y2M1ODU0ZTBhNGEifQ==");
	}

	@Test
	public void validate_noValidators() {
		assertTrue(validator.validate(card));
	}

	@Test
	public void validate_singleValidator() {
		validator.addVerifier(card.getId(), card.getSnapshotModel().getPublicKeyData());

		CardModel validCard = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU1jZWhpXC9ZVXFvZlpVbGdJVmdaRjgzc2ZcL2tObzNNZ0wzQlRmNDVlMWx0eWp1RkhBbWEzMGpCWVBEVDVuY1piQ0gxVXNmekJwbU9US1ZKb2laMXV4ZzQ9IiwiNGYzZWMzY2JlMTFlMTRiY2ZiYjYyNjVhYmYwM2M0YTIxZDYwOThkNGFlZGJjMDZmYjY2OGMyZjYyY2M5M2VmOCI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFEeFJPWFFCV2ZxWjVYdnhlOWRtUlwvWk40akgrNm90eENxWWY3aFcrcDRaN2VVSFhuUytIbDR4MkZibmtFc2xPZDZ0SHRWTGsrRWNvZnBUUWxPNFRad2s9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFUVktOMU00VEhCS1pETnZTbEJqWEM5bE5HUkxaMHg0U0hCSWRIRnNZM1JhVTFoTlVITkxhVXBDVlhGclBTSXNJbWxrWlc1MGFYUjVJam9pT0dVeFlUZzFZVEEwWVRKbFpqWXlZV016T1RCa05qSmhZVGxqTkRjNE5EaG1OV0l3WXpjMFkyVmxPV0ptT0RZM01XUTVNamxqWXpVNE5UUmxNR0UwWVNJc0ltbGtaVzUwYVhSNVgzUjVjR1VpT2lKcFpHVnVkR2wwZVY5allYSmtYMmxrSWl3aWMyTnZjR1VpT2lKaGNIQnNhV05oZEdsdmJpSXNJbWx1Wm04aU9uc2laR1YyYVdObFgyNWhiV1VpT2lKUGJHVnJjMkZ1WkhMaWdKbHpJRTFoWTBKdmIyc2dVSEp2SWl3aVpHVjJhV05sSWpvaWFWQm9iMjVsSW4xOSIsImlkIjoiMzBmYmVhZWUzZDgyZjM0NjA5NmZhOTliZTAxMzlmNmRiM2U0NzIxZjViNWM5ZWVlNTE0NmUwYTM0ODk4ODVkOSJ9");
		assertTrue(validator.validate(validCard));
	}

	@Test
	public void validate_invalid_singleValidator() {
		validator.addVerifier(card.getId(), card.getSnapshotModel().getPublicKeyData());

		CardModel invalidCard = TestUtils.importCard(
				"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUJwVmlWYmhRRDhKbVZUT1JndGsrWHM0ajVqSG13RW1uM1RpL1ZPUC9YWU80WDRFdlpneTlyVWFxZ0trYm8xb1RBUUcvaTBsNHpjM1dyN3QzRUM5OUE0PSIsIjRmM2VjM2NiZTExZTE0YmNmYmI2MjY1YWJmMDNjNGEyMWQ2MDk4ZDRhZWRiYzA2ZmI2NjhjMmY2MmNjOTNlZjgiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRTmdQYndvTUMydGRmTDBcL2FUdmlGZDdoTGI4OGhaNVZjVXdmeTZBb1wvT0lqa3FzYnJKdnROT0RWVGZicXFDUHE1cmlpemxKWjFRbExkK0FCYVBlMUhnND0ifX0sImNvbnRlbnRfc25hcHNob3QiOiJleUp3ZFdKc2FXTmZhMlY1SWpvaVRVTnZkMEpSV1VSTE1sWjNRWGxGUVdwbFVtWmxOMmt4ZVRSWlVHcHlSRGQxYzNjeVN6TlNhMUZEUml0T1YydDFNMFZXTmxCcE9IcHVZMWs5SWl3aWFXUmxiblJwZEhraU9pSTRaVEZoT0RWaE1EUmhNbVZtTmpKaFl6TTVNR1EyTW1GaE9XTTBOemcwT0dZMVlqQmpOelJqWldVNVltWTROamN4WkRreU9XTmpOVGcxTkdVd1lUUmhJaXdpYVdSbGJuUnBkSGxmZEhsd1pTSTZJbWxrWlc1MGFYUjVYMk5oY21SZmFXUWlMQ0p6WTI5d1pTSTZJbUZ3Y0d4cFkyRjBhVzl1SWl3aWFXNW1ieUk2ZXlKa1pYWnBZMlZmYm1GdFpTSTZJazlzWld0ellXNWtjdUtBbVhNZ1RXRmpRbTl2YXlCUWNtOGlMQ0prWlhacFkyVWlPaUpwVUdodmJtVWlmWDA9IiwiaWQiOiJkMGFlZDM2N2E3YzRmYThlZGFkMGQ2MTdmZTYwMDE2M2M0MzMxNmY5MjllNGEwMWVmMTExMGQ5OTFiYzQwMDZlIn0=");
		assertFalse(validator.validate(invalidCard));
	}
}
