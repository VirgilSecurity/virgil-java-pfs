# Client Configuration

To use the Virgil Infrastructure, set up your client and implement the required mechanisms using the following guide.


## Install SDK

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
        <groupId>com.virgilsecurity.pfs</groupId>
        <artifactId>pfs</artifactId>
        <version>1.1.1</version>
    </dependency>
</dependencies>
```


## Obtain an Access Token
When users want to start sending and receiving messages on computer or mobile device, Virgil can't trust them right away. Clients have to be provided with a unique identity, thus, you'll need to give your users the Access Token that tells Virgil who they are and what they can do.

Each your client must send to you the Access Token request with their registration request. Then, your service that will be responsible for handling access requests must handle them in case of users successful registration on your Application server.

```
// an example of an Access Token representation
AT.7652ee415726a1f43c7206e4b4bc67ac935b53781f5b43a92540e8aae5381b14
```

## Initialize SDK

### With a Token
With Access Token, we can initialize the Virgil PFS SDK on the client side to start doing fun stuff like sending and receiving messages. To initialize the **Virgil SDK** on the client side, you need to use the following code:

```java
VirgilApi virgil = new VirgilApiImpl("[YOUR_ACCESS_TOKEN_HERE]");
```

### Without a Token

In case of a **Global Virgil Card** creation you don't need to initialize the SDK with the Access Token. For more information about the Global Virgil Card creation check out the [Creating Global Card guide](/docs/guides/virgil-card/creating-global-card.md).

Use the following code to initialize Virgil SDK without Access Token.

```java
VirgilApi virgil = new VirgilApiImpl();
```
