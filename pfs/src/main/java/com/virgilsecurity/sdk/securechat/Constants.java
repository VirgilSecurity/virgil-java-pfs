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

/**
 * @author Andrii Iakovenko
 *
 */
public interface Constants {

	public interface Errors {

		public interface Migration {
			public interface V1_1 {
				int UNKNOWN_SESSION_STATE = 0x01;
				int IMPORTING_EPH_PRIVATE_KEY = 0x02;
				int IMPORTING_LT_PRIVATE_KEY = 0x03;
				int IMPORTING_OT_PRIVATE_KEY = 0x04;
			}
		}

		public interface SecureChat {
			int OBTAINING_RECIPIENT_CARDS_SET = 0x00001;
			int RECIPIENT_SET_EMPTY = 0x00002;
			int UNKNOWN_MESSAGE_STRUCTURE = 0x00003;
		}

		public interface SessionManager {
			int IMPORTING_INITIATOR_PUBLIC_KEY_FROM_IDENTITY_CARD = 0x00001;
			int VALIDATING_INITIATOR_SIGNATURE = 0x00002;
			int INITIATOR_IDENTITY_CARD_ID_DOESNT_MATCH = 0x00003;
			int GET_RESPONDER_LT = 0x00004;
			int GET_RESPONDER_OT = 0x00005;
			int ADD_VERIFIER = 0x00006;
			int LONG_TERM_CARD_VALIDATION = 0x00007;
			int ONE_TIME_CARD_VALIDATION = 0x00008;
			int REMOVING_OT_KEY = 0x00009;
			int SESSION_NOT_FOUND = 0x00010;
		}

		int OTC_VALIDATION_FAILED = 0x00002;
		int CORRUPTED_SAVED_SESSION = 0x00003;
		int ACTIVE_SESSION_EXISTS = 0x00004;
		int REMOVE_EXPIRES_SESSION = 0x00005;
	}

}
