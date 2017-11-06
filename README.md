  # Virgil .NET/C# PFS SDK

[Installation](#installation) | [Initialization](#initialization) | [Chat Example](#chat-example) | [Register Users](#register-users) | [Documentation](#documentation) | [Support](#support)

[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application.

[Perfect Forward Secrecy](https://developer.virgilsecurity.com/docs/references/perfect-forward-secrecy) for Encrypted Communication allows you to protect previously intercepted traffic from being decrypted even if the main Private Key is compromised.

Virgil __Java PFS SDK__ contains dependent Virgil [Java](https://github.com/VirgilSecurity/virgil-sdk-java-android/tree/v4) package.


To initialize and use Virgil PFS SDK, you need to have [Developer Account](https://developer.virgilsecurity.com/account/signin).

## Installation

The Virgil Java SDK is provided as a package named com.virgilsecurity.sdk. The package is distributed via Maven repository.

### Target

* Java 7+.
* Android API 16+.

### Prerequisites

* Java Development Kit (JDK) 7+
* Maven 3+

### Installing the package

You can easily add SDK dependency to your project, just follow the examples below.

#### Maven

Use this packages for Java projects.

```
<dependency>
    <groupId>com.virgilsecurity.sdk</groupId>
    <artifactId>crypto</artifactId>
    <version>4.3.3</version>
</dependency>
<dependency>
    <groupId>com.virgilsecurity.sdk</groupId>
    <artifactId>sdk</artifactId>
    <version>4.3.3</version>
</dependency>
```

#### Gradle

Use this packages for Android projects.

```
compile 'com.virgilsecurity.sdk:crypto-android:4.3.3@aar'
compile 'com.virgilsecurity.sdk:sdk-android:4.3.3@aar'
compile 'com.google.code.gson:gson:2.7'
```

[Get Started with the Java/Android SDK](https://github.com/VirgilSecurity/virgil-sdk-java-android/tree/v4/docs/get-started).


## Initialization

Be sure that you have already registered at the [Dev Portal](https://developer.virgilsecurity.com/account/signin) and created your application.

To initialize the PFS SDK at the __Client Side__, you need only the __Access Token__ created for a client at [Dev Portal](https://developer.virgilsecurity.com/account/signin).
The Access Token helps to authenticate client's requests.

```java
VirgilApi virgil = new VirgilApiImpl("[ACCESS_TOKEN]");
```

Virgil Java PFS SDK is suitable only for Client Side. If you need Java for Server Side, take a look at this [repository](https://github.com/VirgilSecurity/virgil-sdk-java-android/tree/v4).

In Virgil every user has a **Private Key** and represented with a **Virgil Card (Identity Card)**.

The Virgil Card contains user's Public Key and all information necessary to identify the user.
Click [here](#register-users) to see more details on how to create user's Virgil Card.



## Chat Example

Before chat initialization, every user must have created Virgil Card.
If you have no Virgil Card yet, you can easily create it with our [guide](#register-users).

To begin communicating with PFS technology, every user must run the initialization:

```cs
// initialize Virgil crypto instance
var crypto = new VirgilCrypto();
// enter User's credentials to create OTC and LTC Cards
var preferences = new SecureChatPreferences(
    crypto,
    "[BOB_IDENTITY_CARD]",
    "[BOB_PRIVATE_KEY]",
    "[YOUR_ACCESS_TOKEN_HERE]");

// this class performs all PFS-technology logic: creates LTC and OTL Cards, publishes them, etc.
var chat = new SecureChat(preferences);

// the method is periodically called to:
// - check availability of user's OTC Cards on the service
// - add new Cards till their quantity reaches the number (100) noted in current method
await this.SecureChat.RotateKeysAsync(100);
```

Then Sender establishes a secure PFS conversation with Receiver, encrypts and sends the message:

```java
private void receiveMessage(SecureChat chat, CardModel senderCard, String message) {
    try {
        // load an existing session or establish new one
        SecureSession session = chat.loadUpSession(senderCard, message);

        // decrypt message using established session
        String plaintext = session.decrypt(message);

        // handle a message
        handleMessage(plaintext);
    } catch (Exception e) {
        // Error handling
    }
}
```

Receiver decrypts the incoming message using the conversation he has just created:

```java
private void sendMessage(SecureChat chat, CardModel receiverCard, String message) {
    // get an active session by recipient's card id
    SecureSession session = chat.activeSession(receiverCard.getId());

    if (session == null) {
        // start new session with recipient if session wasn't initialized yet
        session = chat.startNewSession(receiverCard, null);
    }

    sendMessage(session, receiverCard, message);
}

private void sendMessage(SecureSession session, CardModel receiverCard,
    String message) {
        String ciphertext = null;
    try {
        // encrypt the message using previously initialized session
        ciphertext = session.encrypt(message);
    } catch (Exception e) {
        // error handling
        return;
    }

    // send a cipher message to recipient using your messaging service
    sendMessageToRecipient(receiverCard.getSnapshotModel().getIdentity(),
        ciphertext);
}
```

With the open session, which works in both directions, Sender and Receiver can continue PFS-encrypted communication.

__Next:__ Take a look at our [Get Started](/docs/get-started/pfs-encrypted-communication.md) guide to see the whole scenario of the PFS-encrypted communication.

## Register Users

In Virgil every user has a **Private Key** and represented with a **Virgil Card (Identity Card)**.

Using Identity Cards, we generate special Cards that have their own life-time:
* **One-time Card (OTC)**
* **Long-time Card (LTC)**

For each session you can use new OTC and delete it after session is finished.

To create user's Identity Virgil Cards, use the following code:

```cs
// generate a new Virgil Key for Alice
VirgilKey aliceKey = virgil.getKeys().generate();

// save the Alice's Virgil Key into the storage at her device
aliceKey.save("[KEY_NAME]", "[KEY_PASSWORD]");

// create Alice's Virgil Card
VirgilCard aliceCard = virgil.getCards().create(aliceIdentity, aliceKey,
    USERNAME_IDENTITY_TYPE);

// export a Virgil Card to string
String exportedCard = aliceCard.export();
```
after Virgil Card creation it is necessary to sign and publish it with Application Private Virgil Key at the server side.

```cs
// import Alice's Virgil Card from string
VirgilCard importedCard = virgil.getCards().importCard(exportedCard);

// publish the Virgil Card at Virgil Services
virgil.getCards().publish(importedCard);
```
Now, you have user's Virgil Cards and ready to initialize a PFS Chat. During initialization you create OTC and LTC Cards.

Find more examples in our [guide](/docs/get-started/pfs-encrypted-communication.md).

## Documentation

Virgil Security has a powerful set of APIs and the documentation to help you get started:

* [Get Started](/docs/get-started)
  * [PFS Encrypted Сommunication](/docs/get-started/pfs-encrypted-communication.md)
* [Configuration](/docs/guides/configuration)
  * [Set Up PFS Client Side](/docs/guides/configuration/client-pfs.md)
  * [Set Up Server Side](/docs/guides/configuration/server.md)

To find more examples how to use Virgil Cards, take a look at [.NET SDK documentation](https://github.com/VirgilSecurity/virgil-sdk-java-android/blob/v4/README.md)

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support

Our developer support team is here to help you. You can find us on [Twitter](https://twitter.com/virgilsecurity) and [email][support].

[support]: mailto:support@virgilsecurity.com
