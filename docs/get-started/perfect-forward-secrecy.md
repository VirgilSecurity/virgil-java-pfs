# Perfect Forward Secrecy

[Set Up Server](#head1) | [Set Up Clients](#head2) | [Register Users](#head3) | [Initialize PFS Chat](#head4) | [Send & Receive a Message](#head5)

Virgil Perfect Forward Secrecy (PFS) is designed to prevent a possibly compromised long-term secret key from affecting the confidentiality of past communications. In this tutorial, we are helping two people or IoT devices to communicate with end-to-end **encryption** with enabled PFS.

Create a [Developer account](https://developer.virgilsecurity.com/account/signup) and register your Application to get the possibility to use Virgil Infrastructure.

## <a name="head1"></a> Set Up Server
Your server should be able to authorize your users, store Application's Virgil Key and use **Virgil SDK** for cryptographic operations or for some requests to Virgil Services. You can configure your server using the [Setup Guide](/docs/guides/configuration/server-configuration.md).


## <a name="head2"></a> Set Up Clients
Set up the client side to provide your users with an access token after their registration at your Application Server to authenticate them for further operations and transmit their Virgil Cards to the server. Configure the client side using the [Setup Guide](/docs/guides/configuration/client-side-pfs.md).



## <a name="head3"></a> Register Users
Now you need to register the users who will participate in encrypted communications.

To sign and encrypt a message, each user must have his own tools, that allow him to perform cryptographic operations. These tools must contain the information necessary to identify users. In Virgil Security, these tools are the Virgil Key and the Virgil Card.

![Virgil Card](/docs/img/Card_introduct.png "Create Virgil Card")

When we have already set up the Virgil SDK on the server & client sides, we can finally create Virgil Cards for the users and transmit the Cards to your Server for further publication on Virgil Services.


### Generate Keys and Create Virgil Card
To generate a new Key Pair, use Virgil SDK on the client side. Then create user's Virgil Card with recently generated Virgil Key. All keys are generated and stored on the client side.

In this example, we pass on the username and password, which we lock in their private encryption key. Each Virgil Card is signed by user's Virgil Key. This guarantees Virgil Card content integrity over its life cycle.

```java
// generate a new Virgil Key
VirgilKey aliceKey = virgil.getKeys().generate();

// save the Virgil Key into storage
aliceKey.save("[KEY_NAME]", "[KEY_PASSWORD]");

// create a Virgil Card
VirgilCard aliceCard = virgil.getCards().create(aliceIdentity, aliceKey,
    USERNAME_IDENTITY_TYPE);
```

**Warning**: Virgil doesn't keep a copy of your Virgil Key. If you lose a Virgil Key, there is no way to recover it.

To enable the Sender to send a message, we also need a Virgil Card associated with the Recipient.
**Note**: Recently created user Virgil Cards will be visible only for application users because they are related to the Application.

Read more about Virgil Cards and their types [here](/docs/guides/virgil-card/creating-card.md).


### Transmit the Cards to Your Server

Next, you must serialize and transmit these cards to your server, where you will approve and publish user's Cards.

```java
// Export Virgil Card
String exportedCard = aliceCard.export();

// transmit the to the server
transmitToServer(exportedCard);
```

Use the [approve & publish users guide](/docs/guides/configuration/server-configuration.md) to publish users Virgil Cards on Virgil Services.



## <a name="head4"></a> Initialize PFS Chat
With the user's Cards in place, we are now ready to initialize a PFS chat. In this case, we will use the Recipient's Private Keys, the Virgil Cards and the Access Token.

To begin communicating, Bob must run the initialization:

```java
// Initialize PFS chat (bob)
SecureChatContext bobChatContext = new SecureChatContext(bobCard.getModel(),
    bobKeys.getPrivateKey(), context.getCrypto(), ctx);

bobChatContext.setKeyStorage(new VirgilKeyStorage());
bobChatContext.setDeviceManager(new DefaultDeviceManager());
bobChatContext.setUserDefaults(new DefaultUserDataStorage());
SecureChat bobChat = new SecureChat(bobChatContext);

aliceChat.rotateKeys(5);
```

**Warning**: If Bob does not run the chat initialization, Alice cannot create an initial message.

Then, Alice must run the initialization:

```java
// Initialize PFS chat (alice)
SecureChatContext aliceChatContext = new SecureChatContext(aliceCard.getModel(),
    aliceKeys.getPrivateKey(), context.getCrypto(), ctx);

aliceChatContext.setKeyStorage(new VirgilKeyStorage());
aliceChatContext.setDeviceManager(new DefaultDeviceManager());
aliceChatContext.setUserDefaults(new DefaultUserDataStorage());
SecureChat aliceChat = new SecureChat(aliceChatContext);

aliceChat.rotateKeys(5);
```

After chat initialization, Alice and Bob can start their PFS communication.

## <a name="head5"></a> Send & Receive a Message

Once Recipients initialized a PFS Chat, they can communicate.

Alice establishes a secure PFS conversation with Bob, encrypts and sends the message to him:

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


Then Bob decrypts the incoming message using the conversation he has just created:


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

With the open session, that works in both directions, Alice and Bob can continue PFS encrypted communication.
