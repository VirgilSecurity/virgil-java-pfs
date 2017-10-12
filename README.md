# Introduction

Virgil Perfect Forward Secrecy (PFS) is designed to prevent a possibly compromised long-term secret key from affecting the confidentiality of past communications. In this tutorial, we will be helping two people or IoT devices to communicate with end-to-end encryption with PFS enabled.

# Get started

Read [Get started](https://developer.virgilsecurity.com/docs/java/get-started/perfect-forward-secrecy) document which describes common cases of Virgil PFS usage.

# Migration manual

## Migrate to 1.1 from 1.0

### Release notes

- Added multiple sessions support

### Update client dependencies

#### Maven

```
<dependencies>
    <dependency>
        <groupId>com.virgilsecurity.sdk</groupId>
        <artifactId>crypto</artifactId>
        <version>4.5.0</version>
    </dependency>
    <dependency>
        <groupId>com.virgilsecurity.pfs</groupId>
        <artifactId>pfs</artifactId>
        <version>1.1.1</version>
    </dependency>
</dependencies>
```

#### Gradle (Android)

```
compile 'com.virgilsecurity.sdk:crypto-android:4.5.0@aar'
compile 'com.virgilsecurity.sdk:sdk-android:4.5.0@aar'
compile 'com.virgilsecurity.pfs:pfs-android:1.1.1@aar'
compile 'com.google.code.gson:gson:2.7'
````

### Source code changes

Common changes are
- Changed structure of data stored in DataStorage
- New key attributes stored in KeyStorage. See `com.virgilsecurity.sdk.securechat.keystorage.JsonFileKeyStorage`

There is a new interface `com.virgilsecurity.sdk.securechat.keystorage.KeyStorage` which extends `com.virgilsecurity.sdk.storage.KeyStorage` adding bulk operations with key entries.
The default implemetation is `com.virgilsecurity.sdk.securechat.keystorage.JsonFileKeyStorage` which is similar to `com.virgilsecurity.sdk.storage.DefaultKeyStorage`.

`com.virgilsecurity.sdk.securechat.SecureSession` class
- Class moved to `com.virgilsecurity.sdk.securechat.session` package
- No more `creationDate` parameter. Just skip it
- No more `isInitialized` method. Use `SecureChat.activeSession` method to get active session for specific recipient. If there is no session, then create a new one with `SecureChat.startNewSession`. Get session with `SecureChat.loadUpSession` method for every incoming message.

Configure `SecureChat` with `com.virgilsecurity.sdk.securechat.SecureChatContext`
- Define long term key time to live in seconds with `setLongTermKeysTtl` method
- Define time during which expired long-term key is not removed with `setExpiredLongTermKeysTtl` method
- Define session time to live in seconds with `setSessionTtl` method
- Define time during which expired session key is not removed with `setExpiredSessionTtl` method
- Define time during which one-time key is not removed after sdk determined that it was exhausted with `setExhaustedOneTimeKeysTtl` method

`com.virgilsecurity.sdk.securechat.SecureChat` class
- added additional data parameter to `SecureChat.loadUpSession` method 
- `setUserDefaults` method renamed to `setUserDataStorage`
- added `sessionId` parameter to `removeSession` method. Use `removeSession` when you need to remove specific session
- added `removeSessions` method. Use it when you need to remove all sessions with specific recipient
- call `gentleReset` method to remove all sessions and pfs-related keys for current user

It's a good case to obtain existing session with `SecureChat.activeSession` before starting a new session. If no session found, then create a new one with `SecureChat.startNewSession` method. It's the most preferable case.

Don't cache `SecureSession`, get session instance from `SecureChat` with every message.


### Data migration

Call `initialize();` method of `SecureChat` instance right after `SecureChat` intance created. It will migrate structure of the data stored by previous version.
