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
package com.virgilsecurity.sdk.securechat.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.securechat.UserDataStorage;

/**
 * @author Andrii Iakovenko
 *
 */
public class DefaultUserDataStorageTest {

    private UserDataStorage dateStorage;
    private String storageName;

    @Before
    public void setUp() {
        dateStorage = new DefaultUserDataStorage();
        storageName = UUID.randomUUID().toString();
    }

    @Test
    public void getAllData_notExists() {
        Map<String, String> data = dateStorage.getAllData(storageName);
        assertNotNull(data);
        assertTrue(data.isEmpty());
    }

    @Test
    public void getAllData() {
        dateStorage.addData(storageName, "key1", "value1");
        Map<String, String> data = dateStorage.getAllData(storageName);
        assertNotNull(data);
        assertEquals(1, data.size());
        assertEquals("value1", data.get("key1"));
    }

    @Test
    public void getData() {
        dateStorage.addData(storageName, "key1", "value1");
        assertEquals("value1", dateStorage.getData(storageName, "key1"));
        assertNull(dateStorage.getData(storageName, "key2"));
    }

}
