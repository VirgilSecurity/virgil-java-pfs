# Encrypted Communication

 [Set Up Server](#head1) | [Set Up Clients](#head2) | [Register Users](#head3) | [Initialize PFS Chat](#head4) | [Send & Receive Message](#head5)

Virgil Perfect Forward Secrecy (PFS) is designed to prevent a possibly compromised long-term secret key from affecting the confidentiality of past communications. In this tutorial, we will be helping two people or IoT devices to communicate with end-to-end encryption with PFS enabled.


## <a name="head1"></a> Set Up Server
Your server should be able to authorize your users, store Application's Virgil Key and use **Virgil SDK** for cryptographic operations or for some requests to Virgil Services. You can configure your server using the [Setup Guide](/docs/guides/configuration/server-configuration.md).


## <a name="head2"></a> Set Up Clients
Set up the client side. After users register at your Application Server, provide them with an access token that authenticates users for further operations and transmit their **Virgil Cards** to the server. Configure the client side using the [Setup Guide](/docs/guides/configuration/client-configuration.md).


## <a name="head3"></a> Register Users
Now you need to register the users who will participate in encrypted communications.

To sign and encrypt a message, each user must have his own tools, which allow him to perform cryptographic operations. These tools must contain the necessary information to identify users. In Virgil Security, such tools are the Virgil Key and the Virgil Card.

![Virgil Card](/docs/img/Card_introduct.png "Create Virgil Card")

When we have already set up the Virgil SDK on the server and client sides, we can finally create Virgil Cards for the users and transmit the Cards to your Server for further publication on Virgil Services.


### Generate Keys and Create Virgil Card
Use the Virgil SDK on the client side to generate a new Key Pair. Then, with recently generated Virgil Key, create user's Virgil Card. All keys are generated and stored on the client side.

In this example, we are passing on the user's username and a password, which will lock in their private encryption key. Each Virgil Card is signed by user's Virgil Key, which guarantees the Virgil Card content integrity over its life cycle.

```java
// generate a new Virgil Key
VirgilKey aliceKey = virgil.getKeys().generate();

// save the Virgil Key storage
aliceKey.save("[KEY_NAME]", "[KEY_PASSWORD]");

// create a Virgil Card
VirgilCard aliceCard = virgil.getCards().create("[ALICE_IDENTITY]",
        aliceKey, "[USER_IDENTITY_TYPE]");
```

**Warning**: Virgil doesn't keep a copy of your Virgil Key. If you lose a Virgil Key, there is no way to recover it.

**Note**: Recently created users' Virgil Cards are visible only for application users because they are related to the Application.

Read more about Virgil Cards and their types [here](/docs/guides/virgil-card/creating-card.md).


### Transmit the Cards to Your Server

Next, you must serialize and transmit these Cards to your server, where you will approve and publish users' Cards.

```java
// export the Virgil Card to string
String exportedCard = aliceCard.export();

// transmit the Virgil Card to the server
transmitToServer(exportedCard);
```

Use the [approve & publish users guide](/docs/guides/configuration/server-configuration.md#-approve--publish-cards) to publish users Virgil Cards on Virgil Services.


## <a name="head4"></a> Initialize PFS Chat

With the user's Cards in place, we are now ready to initialize a PFS chat. In this case, we will use the Recipient's Private Keys, the Virgil Cards and the Access Token.
In order to begin communicating, Bob must run the initialization:

```java
// Initialize PFS chat (bob)
Crypto crypto = new VirgilCrypto();

VirgilPFSClientContext bobPfsCtx =
        new VirgilPFSClientContext("[ACCESS_TOKEN]");
SecureChatContext bobChatContext = new SecureChatContext(
        bobCard.getModel(), bobKey.getPrivateKey(), crypto, bobPfsCtx);

bobChatContext.setKeyStorage(new JsonFileKeyStorage());
bobChatContext.setDeviceManager(new DefaultDeviceManager());
bobChatContext.setUserDataStorage(new DefaultUserDataStorage());
SecureChat bobChat = new SecureChat(bobChatContext);

bobChat.rotateKeys(5);
```

Then, Alice must run the initialization:

```java
// Initialize PFS chat (alice)
VirgilPFSClientContext alicePfsCtx =
        new VirgilPFSClientContext("[ACCESS_TOKEN]");
SecureChatContext aliceChatContext = new SecureChatContext(
        aliceCard.getModel(), aliceKey.getPrivateKey(), crypto,
        alicePfsCtx);

aliceChatContext.setKeyStorage(new JsonFileKeyStorage());
aliceChatContext.setDeviceManager(new DefaultDeviceManager());
aliceChatContext.setUserDataStorage(new DefaultUserDataStorage());
SecureChat aliceChat = new SecureChat(aliceChatContext);

aliceChat.rotateKeys(5);
```
After chat initialization, Alice and Bob can start their PFS communication.


## <a name="head5"></a> Send & Receive Message

Once Recipients initialized a PFS Chat, they can communicate.
Alice establishes a secure PFS conversation with Bob, encrypts and sends the message to him:

```java
private void receiveMessage(SecureChat chat, CardModel senderCard,
        String message) {
    try {
        // load an existing session or establish new one
        SecureSession session = chat.loadUpSession(senderCard, message, null);
        
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
private void sendMessage(SecureChat chat, CardModel receiverCard,
        String message) {
    // get an active session by recipient's card id
    SecureSession session = chat.activeSession(receiverCard.getId());
    
    if (session == null) {
        // start new session with recipient if session wasn't initialized yet
        try {
            session = chat.startNewSession(receiverCard, null);
        } catch (CardValidationException e) {
            // error handling
            return;
        } catch (SecureChatException e) {
            // error handling
            return;
        }
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
With the open session, which works in both directions, Alice and Bob can continue PFS encrypted communication.
