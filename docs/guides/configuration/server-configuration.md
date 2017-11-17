# Server Configuration
[Developer Account](#head1) | [Install SDK](#head2) | [Initialize SDK](#head3) | [Create Access Token](#head4) | [Approve & Publish Cards](#head5)

This guide helps you to set up your server and implement required mechanisms using Virgil Infrastructure.

## <a name="head1"></a> Developer Account

To use the Virgil SDK package, you need to sign up for a **Developer account** and create your first application. Make sure to save the **App ID**, the **App Key** and the **App Key Password**. If you did not create a Developer account yet, you can do so now by using this [link](https://developer.virgilsecurity.com/account/signup).

## <a name="head2"></a> Install SDK

The Virgil Java SDK is provided as a package named com.virgilsecurity.sdk. The package is distributed via Maven repository.

The package is available for:
- Java 7 and newer
- Android API 16 and newer

Prerequisites:
- Java Development Kit (JDK) 7+
- Maven 3+

Installing the package:

You can easily add SDK dependency to your project, just follow the examples below (Maven):

```java
<dependencies>
    <dependency>
        <groupId>com.virgilsecurity.sdk</groupId>
        <artifactId>crypto</artifactId>
        <version>4.5.0</version>
    </dependency>
    <dependency>
        <groupId>com.virgilsecurity.sdk</groupId>
        <artifactId>sdk</artifactId>
        <version>4.5.0</version>
    </dependency>
</dependencies>
```


## <a name="head3"></a> Initialize SDK
To initialize the **Virgil SDK** on a server, you need to sign up for a developer account and create your first application. Then, initialize the SDK using:
1. The **access token** for your application
2. The application **credentials** (the App ID, the App Key in a file, the App Key password).

```java
AppCredentials credentials = new AppCredentials();
credentials.setAppId("[APPLICATION_ID]");
credentials.setAppKey(VirgilBuffer.from("[APP_PRIVATE_KEY]"));
credentials.setAppKeyPassword("[APP_PRIVATE_KEY_PASSWORD]");

VirgilApiContext ctx = new VirgilApiContext("[ACCESS_TOKEN]");
ctx.setCredentials(credentials);

VirgilApi virgil = new VirgilApiImpl(ctx);
```



## <a name="head4"></a> Create an Access Token

When users want to start working with your Application in a browser or mobile device, Virgil can't trust them right away. Virgil needs the developer to vouch for his users, so we can trust them too. You need to give your users an Access Token that tells Virgil who they are and what they can do. Thus, you need a service responsible for an access token creation in your Virgil Developer Dashboard for users registered on your server.

You must decide, based on the token request that was sent to you, who the user is and what they should be allowed to do and then you have to transfer a recently create access token to the client side. To figure out who the user is, you might implement the users authentication mechanism by using the user's identity. Also, you can assign a temporary identity to the user if you don't care who he is.

```
// an example of an Access Token representation
AT.7652ee415726a1f43c7206e4b4bc67ac935b53781f5b43a92540e8aae5381b14
```


## <a name="head5"></a> Approve & Publish Cards

You have to transfer recently created and signed users' **Virgil Cards** from the client side to your server for further approving. When you receive users' Virgil Cards from the client side, import them, sign with your App Key using Virgil SDK and Publish to the **Virgil Services**. Thus, you need a service that validates and signs the transferred users' Virgil Cards.

Use the following code to Import and Publish a Virgil Card to Virgil Services.

```java
// import a Virgil Card from string
VirgilCard importedCard = virgil.getCards().importCard(exportedCard);

// publish a Virgil Card
virgil.getCards().publish(importedCard);
```

At the Virgil Services, the Virgil Card(s) will be also signed. Developers can verify the signature of the Virgil Card owner, the Virgil Services, and the Application Server at any time.

To find more examples of Card Validation, see our guide on [Validating Cards](/docs/guides/virgil-key/generating-key.md).
