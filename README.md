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
compile 'com.virgilsecurity.pfs:pfs-android:1.1.1-SNAPSHOT@aar'
compile 'com.google.code.gson:gson:2.7'
````

### Source code changes

- New key attributes stored in KeyStorage. See `com.virgilsecurity.sdk.securechat.keystorage.JsonFileKeyStorage`.
- `setUserDefaults` method of `com.virgilsecurity.sdk.securechat.SecureChat` class renamed to `setUserDataStorage`
- Changed structure of data stored in DataStorage
- `com.virgilsecurity.sdk.securechat.SecureSession` class moved to `com.virgilsecurity.sdk.securechat.session` package
- added additional data parameter to `SecureChat.loadUpSession` method

### Data migration

Call `initialize();` method of `SecureChat` instance right after `SecureChat` intance created. It will migrate structure of the data stored by previous version.
