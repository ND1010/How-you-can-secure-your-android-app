<p align="center">
<img alt="HashCodeGeneration" src="https://miro.medium.com/max/700/1*ZebUrjnenSmQgBf5ddjpXg.png">
</p>

# How you can secure your app?
# Hash-code-generation-Singing-apk.

## Prepared and maintained by [Dhruv Nirmal](https://github.com/nd1010) who is having experience of Android development, Security & financial services(Fin Tech).

## Contents - How you can secure your app?

* [Introduction](#introduction-security)
* [Encrypt your data](#encrypt-your-data)
* [Detect insecure devices](#detect-insecure-devices)
* [Authenticate users and keys with biometrics](#authenticate-users-and-keys-with-biometrics)
* [Communicate securely](#communicate-securely)
* [Address issues found by Google Play](#address-issues-found-by-google-play)
* [Be the first to know](#be-the-first-to-know)
* [Test, test, and test again](#Test,-est,-nd-test-again)
* [Audit third-party libraries](#audit-third-party-libraries)



## Contents - Hash-code-generation-Singing-apk

* [Introduction](#introduction)
* [Methods to Sign in App](#methods-to-sign-in-app)
* [Get Key Fingerprints](#get-key-fingerprints)
* [Tools You need](#tools-you-need)
* [Other Security Stuffs](#other-security-stuffs)


### Introduction Security

-Our goal is to make Android the safest mobile platform in the world. That's why we consistently invest in technologies that bolster the security of the platform, its apps, and the global Android ecosystem.
-It's a responsibility we share with you, as developers, to keep users safe and secure.


### Encrypt your data

- The Security library provides an implementation of the [security best practices](https://developer.android.com/topic/security/best-practices) related to reading and writing data at rest, as well as key creation and verification.
- The library uses the builder pattern to provide safe default settings for the following security levels:
    - Strong security that balances great encryption and good performance. This level of security is appropriate for consumer apps, such as banking and chat apps, as well as enterprise apps that perform certificate revocation checking.
    - Maximum security. This level of security is appropriate for apps that require a hardware-backed keystore and user presence for providing key access.
    - **Key management**
    	- A **keyset** that contains one or more keys to encrypt a file or shared preferences data. The keyset itself is stored in `SharedPreferences`. 
    	- A **primary (master) key** that encrypts all keysets. This key is stored using the Android keystore system.
    - **Classes included in library**
    	- **EncryptedFile:** Provides custom implementations of `FileInputStream` and `FileOutputStream`, granting your app more secure streaming read and write operations.
    	- **EncryptedSharedPreferences:** Wraps the SharedPreferences class and automatically encrypts keys and values using a two-scheme method:
    		- **Keys** are encrypted using a deterministic encryption algorithm such that the key can be encrypted and properly looked up.
    		- **Values** are encrypted using AES-256 GCM and are non-deterministic.
    
	- **The following sections show how to use these classes to perform common operations with files and shared preferences.**
		- To use the Security library, add the following dependency to your app module's build.gradle file:
			
```
			dependencies {
			implementation "androidx.security:security-crypto:1.0.0-rc04"

			// For Identity Credential APIs
			implementation "androidx.security:security-identity-credential:1.0.0-alpha02"
			}
```

Read Files The following code snippet demonstrates how to use EncryptedFile to read the contents of a file in a more secure way:

```kotlin

	// Although you can define your own key generation parameter specification, it's
	// recommended that you use the value specified here.
	val mainKey = MasterKey.Builder(applicationContext)
	.setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
	.build()
	val fileToRead = "my_sensitive_data.txt"
	val encryptedFile = EncryptedFile.Builder(
	applicationContext,
	File(DIRECTORY, fileToRead),
	mainKey,
	EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
	).build()

	val inputStream = encryptedFile.openFileInput()
	val byteArrayOutputStream = ByteArrayOutputStream()
	var nextByte: Int = inputStream.read()
	while (nextByte != -1) {
	byteArrayOutputStream.write(nextByte)
	nextByte = inputStream.read()
	}

	val plaintext: ByteArray = byteArrayOutputStream.toByteArray()

```

Write files The following code snippet demonstrates how to use `EncryptedFile` to write the contents of a file in a more secure way:

```kotlin

	// Although you can define your own key generation parameter specification, it's
	// recommended that you use the value specified here.
	val mainKey = MasterKey.Builder(applicationContext)
	.setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
	.build()

	// Create a file with this name, or replace an entire existing file
	// that has the same name. Note that you cannot append to an existing file,
	// and the file name cannot contain path separators.
	val fileToWrite = "my_sensitive_data.txt"
	val encryptedFile = EncryptedFile.Builder(
	applicationContext,
	File(DIRECTORY, fileToWrite),
	mainKey,
	EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
	).build()

	val fileContent = "MY SUPER-SECRET INFORMATION"
	.toByteArray(StandardCharsets.UTF_8)
	encryptedFile.openFileOutput().apply {
	write(fileContent)
	flush()
	close()
	}

```

**For use cases requiring additional security, complete the following steps:**

1. Create a `KeyGenParameterSpec.Builder` object, passing `true` into [setUserAuthenticationRequired()](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationRequired(boolean)) and a value greater than 0 into [setUserAuthenticationValidityDurationSeconds().](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationValidityDurationSeconds(int))
2. Prompt the user to enter credentials using createConfirmDeviceCredentialIntent(). Learn more about how to request [user authentication for key use.](https://developer.android.com/training/articles/keystore#UserAuthentication)
3. Override `onActivityResult()` to get the confirmed credential callback.


For more information, see [Requiring user authentication for key use.](https://developer.android.com/training/articles/keystore#UserAuthentication)

Edit shared preferences : 
The following code snippet demonstrates how to use `EncryptedSharedPreferences` to edit a user's set of shared preferences in a more secure way:

```kotlin
	val sharedPrefsFile: String = FILE_NAME
	val sharedPreferences: SharedPreferences = EncryptedSharedPreferences.create(
		applicationContext,
		sharedPrefsFile,
		mainKey,
		EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
		EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
	)

	with (sharedPreferences.edit()) {
	    // Edit the user's shared preferences...
	    apply()
	}
```

### Detect insecure devices

- Rooted or unlocked devices, or emulators may fail to protect user data and expose your app to attack. Use SafetyNet Attestation to determine if a device running your app has been tampered with. Based on the results from SafetyNet Attestation, consider acting to protect your app’s content.
- The SafetyNet Attestation API is an anti-abuse API that allows app developers to assess the Android device their app is running on. The API should be used as a part of your abuse detection system to help determine whether your servers are interacting with your genuine app running on a genuine Android device.
- The SafetyNet Attestation API provides a cryptographically-signed attestation, assessing the device's integrity. In order to create the attestation, the API examines the device's software and hardware environment, looking for integrity issues, and comparing it with the reference data for approved Android devices. The generated attestation is bound to the nonce that the caller app provides. The attestation also contains a generation timestamp and metadata about the requesting app.

- The API is not designed to fulfill the following use cases
	- Act as a stand-alone anti-abuse or app-security mechanism. Please use it in combination with the published [best practices for app security](https://developer.android.com/topic/security/best-practices) and your suite of product-specific anti-abuse signals.
	- Function when the device isn't connected to the internet. The API returns an error in such scenarios.
	- Have its response interpreted directly in the calling app. Move all anti-abuse decision logic to a server under your control.
	- Provide fine-grained signals about system modifications. The API offers boolean values that express different levels of system integrity.
	- Contain signals for app-specific use-cases, such as device identifiers, GPS emulation status, and screen lock status.
	- Replace or implement strong DRM checks.
	- Purely to check whether the device is rooted, as the API is designed to check the overall integrity of the device.



# Hash-code-generation-Singing-apk

### Introduction

- An android developer A ,develops an app and placed it in playstore.What if any person b ,somewhat got the password for paystore console.He can easily manipulate(updated the app with malicious code ) 
- on existing the apps of A.
- How google people know ,whether the updated app  came from authorized person/developer ?
- So to tackle this problem,Super Intelligent people designs:- SSL/HTTP  --> in internet World
- Similarly in Android we have to Sign the App with our credentials(private key/public keys) .

#### How it works ?

- We first generate ,keystore file in any fomat like .jks , .keystore  etc  by using a utility Keytool ,present in java jdk  
- generlly located at
    - C:\Program Files\Java\jre1.8.0_91\bin   
- Note Your java(jre1.8.0_91) version may we different ,so just dig a bit ,at you will get right
- Now you can use this keyStore files(.jks or .keystores) to sign the App.



####  How will it protects google people and developer ?

- KeyStore has Private key ,Public Key and many other data.
- After signing an app ,and placing in playstore ,Playstore has public key of that app.
- So when next any body want to update the app in playstore ,one need to sign in the app with it private key.
- And playstore can check it authenticity by using available public key of that app .
- you cant update application without same keystore value else app show different signature. for example you installed an app from playstore after some days if an update come for application then you will only be able to update previous app if its signature and new app signature is same.
- So keep your KeyStore save ,other wise you can't able to update your app in playstore.And i am sure you know the consequence of this.
-You will surprise to know that ,when ever you debug the app it singed with KeyStore evey time.
- Now i know ,What you will Ask ,i have't done this any time, So this is automatically done by android sdk.

- So listen carefully
    - There are two build modes in android
    - `debug mode`: when you are developing and testing your application.
    - `release mode` :when you want to build a release version of your application that you can distribute directly to users or publish on an application marketplace such as Google Play.
    -The Android build process signs your application differently depending on which build mode you use to build your application.

    - When you build in debug mode the Android SDK build tools use the Keytool utility (included in the JDK) to create a debug key. Because the SDK build tools created the debug key, they know the debug key's alias and password. Each time you compile your application in debug mode, the build tools use the debug key along with the Jarsigner utility (also included in the JDK) to sign your application's .apk file. Because the alias and password are known to the SDK build tools, the tools don't need to prompt you for the debug key's alias and password each time you compile.

    - When you build in release mode you use your own private key to sign your application. If you don't have a private key, you can use the Keytool utility to create one for you. When you compile your application in release mode, the build tools use your private key along with the Jarsigner utility to sign your application's .apk file. Because the certificate and private key you use are your own, you must provide the password for the keystore and key alias.

    - The debug signing process happens automatically when you run or debug your application using Eclipse with the ADT plugin. Debug signing also happens automatically when you use the Ant build script with the debug option. You can automate the release signing process by using the Eclipse Export Wizard or by modifying the Ant build script and building with the release option.

- You May some found deug.keystore or release.keystore ,these are keystore files
- `debug.keystore` file is merely for developing and testing purposes, so using that you can't release your app to Google Play using that only.
- Caution: You cannot release your application to the public when signed with the debug certificate.
- `release.keystore` file is required only when you want to release your app to Google Play.


### Methods to Sign in App

1)By using Keytool + android Studio

2)All by Android Studio itself. (New method)

- Method 1:By using Keytool + android Studio
    - open cmd and got to
    - C:\Program Files\Java\jre1.8.0_91\bin 
    - then run `keytool -genkey -v -keystore anyName.keystore -storepass yourPassword -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000`

        ```
        Keystore name: "anyName.keystore"
        Keystore password: "yourPassword"
        Key alias: "androiddebugkey"
        Key password: "android"
        CN: "CN=Android Debug,O=Android,C=US"  
        ```

    - write any value that suits you
    - Then use android studio

- Method 2:Recommended
    - Go to build option in Android studio then ,generate signed apk
    - There you can generate .jks file ,and use this to sign the app
    - Keep the .jks file save ,for future uses


### Get Key Fingerprints

- To hook your app up with services like Google APIs you'll need to print out each of your keys' fingerprints and give them to the services you're using. To do that, use:
    
    ```$ keytool -list -v -keystore [keystore path] -alias [alias-name] -storepass [storepass] -keypass [keypass]```

#### Some commands:-

- http://alvinalexander.com/java/java-keytool-keystore-certificates

- http://alvinalexander.com/java/java-using-keytool-genkey-private-key-keystore

- http://alvinalexander.com/java/java-keytool-keystore-certificates

- http://alvinalexander.com/java/java-using-keytool-list-query

- http://alvinalexander.com/java/java-using-keytool-certificate-file-create

- https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores

#### 1) View Java keystore information with "keytool list"

  `keytool -list -v -keystore privateKey.store`

  - In this example, the name of my keystore file is `privateKey.store`, and the -list and -v (verbose) options tell the keytool command that I want to "list the contents" of the keystore file.
  - OutPut will be ,you will prompt to enter password. 
  - Enter keystore password:  ABC123
      - Keystore type: jks
      - Keystore provider: SUN

- Your keystore contains 2 entries

    ```Alias name: foo
    Creation date: Apr 25, 2010
    Entry type: keyEntry
    Certificate chain length: 1
    Certificate[1]:
    Owner: CN=Alvin Alexander, OU=Application Development, O=devdaily.com, L=Louisville, ST=KY, C=US
    Issuer: CN=Alvin Alexander, OU=Application Development, O=devdaily.com, L=Louisville, ST=KY, C=US
    Serial number: 4bd4e793
    Valid from: Sun Apr 25 17:08:35 AKDT 2010 until: Sat Jul 24 17:08:35 AKDT 2010
    Certificate fingerprints:
	     MD5:  55:20:B2:68:FD:0F:4E:BF:D5:E5:D5:04:47:6C:E3:10
	     SHA1: 25:17:A0:CA:86:CC:3E:6C:2D:C0:4E:8D:E8:33:05:F7:4B:50:FE:E5```



#### 2) Java keytool import - Import a certificate into a public keystore

- http://alvinalexander.com/java/java-using-keytool-import-certificate-keystore

- Assuming that you've been given a certificate file named "certfile.cer" which contains an alias named "foo", you can import it into a public keystore named "publicKey.store" with the following keytool import command:

- `keytool -import -alias foo -file certfile.cer -keystore publicKey.store`

- This import command can be read as:
    - Read from the certfile file named certfile.cer.
    - Look in that file for an alias named "foo".
    - If you find the alias "foo", import the information into the keystore named "publicKey.store".
    - Note: The file publicKey.store may already exist, in which case the public key for "foo" will be added to that keystore file; otherwise, publicKey.store will be created.
    - Java keytool import - a complete example
    - Here's the actual input and output from a Java keytool import example. Hopefully you can use the description I just provided to understand how this command works:
        - `$ keytool -import -alias publicCertFromAl -file certfile.cer -keystore publicKey.store`

    ```Enter keystore password:  BARBAZ
    Owner: CN=Alvin Alexander, OU=Application Development, O=devdaily.com, L=Louisville, ST=KY, C=US
    Issuer: CN=Alvin Alexander, OU=Application Development, O=devdaily.com, L=Louisville, ST=KY, C=US
    Serial number: 4bd4e793
    Valid from: Sun Apr 25 17:08:35 AKDT 2010 until: Sat Jul 24 17:08:35 AKDT 2010
    Certificate fingerprints:
        MD5:  55:20:B2:68:FD:0F:4E:BF:D5:E5:D5:04:47:6C:E3:10
        SHA1: 25:17:A0:CA:86:CC:3E:6C:2D:C0:4E:8D:E8:33:05:F7:4B:50:FE:E5
    Trust this certificate? [no]:  yes
    Certificate was added to keystore
    ```
    
- A few important points here about this output:

    - The alias used here (publicCertFromAl) does not have to correspond to the alias used when the private key keystore and certificate file were created.
The password shown above is the password for the keystore named publicKey.store.
At this point, assuming everything worked, you probably don't need the intermediate certificate file, so you can delete it. To be sure though, you should test that the public key is now in your keystore file. You can do this by attempting to use the public key for whatever your purpose is

#### 3) Java keytool - create a certificate file from a private key (keystore)
    - http://alvinalexander.com/java/java-using-keytool-certificate-file-create

- KeyStore
    - keyStore in Java stores private key and certificates corresponding to there public keys.
    - KeyStore file is use to authenticate yourself to anyone who is asking.It isn.t restricted to just signing .apk files,you can use it to store personal certificates,sign data to be transmitted and a whole variety of authentication.
    - A keystore can be a repository where private keys, certificates and symmetric keys can be stored. This is typically a file.
    - A keystore is a container of certificates, private keys etc.
    - Java Keytool stores the keys and certificates in what is called a keystore.
    - There are specifications of what should be the format of this `keystore` like `.jks` , `.keystore` etc

- Their are various  file extensions(formats) of KeyStore
    - `.jks` -->  binary Java Key Store , default by java ,also used in android
    - `.keystore` -->also used in android
    - `.p12` or `.pfx` `.fot` type  PKS#12 -->  PKCS#12 isn't Java-specific 
    - `.bks`  --> also used in android and many more


### Tools You need


#### 1) OpenSSL

- To generate RSA private keys and Certificate Signing Requests (CSRs), checksums, managing certificates and performing encryption/decryption.
- OpenSSL is a general purpose cryptography library that provides an open source implementation of the Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols.
- The library includes tools for generating RSA private keys and Certificate Signing Requests (CSRs), checksums, managing certificates and performing encryption/decryption. OpenSSL is written in C, but wrappers are available for a wide variety of computer languages.
- As of this writing, it’s estimated that 66% of all Web servers use OpenSSL. The OpenSSL toolkit is licensed under an Apache-style license.
- You can generate your application signature (keyhash) using keytool that comes with java. But to generate signature you need openssl installed on your pc. If you don’t have one download openssl from [here](https://code.google.com/archive/p/openssl-for-windows/downloads)

    - (If you have a 64 bit machine you must download openssl-0.9.8e X64 not the latest version)



#### 2) keytool

- Is utility tool available in java
- The keytool command is a key and certificate management utility. It enables users to administer their own public/private key pairs and associated certificates for use in self-authentication (where the user authenticates himself or herself to other users and services) or data integrity and authentication services, using digital signatures.
- The keytool command also enables users to cache the public keys (in the form of certificates) of their communicating peers.
- Java Keytool stores the keys and certificates in what is called a keystore.By default the Java keystore is implemented as a file. It protects private keys with a password. A Keytool keystore contains the private key and any certificates necessary to complete a chain of trust and establish the trustworthiness of the primary certificate.
- Each certificate in a Java keystore is associated with a unique alias. When creating a Java keystore you will first create the .jks file that will initially only contain the private key. You will then generate a CSR and have a certificate generated from it. Then you will import the certificate to the keystore including any root certificates. Java Keytool also several other functions that allow you to view the details of a certificate or list the certificates contained in a keystore or export a certificate.
- A certificate is a digitally signed statement from one entity (person, company, and so on.), that says that the public key (and some other information) of some other entity has a particular value. (See Certificate.) When data is digitally signed, the signature can be verified to check the data integrity and authenticity. Integrity means that the data has not been modified or tampered with, and authenticity means the data comes from whoever claims to have created and signed it.

- The keytool command also enables users to administer secret keys and passphrases used in symmetric encryption and decryption (DES).
- The keytool command stores the keys and certificates in a keystore

- A KeyStore is a repository of security certificates – either authorization certificates or public key certificates – used for instance in SSL encryption.

- If you have jdk in your pc, then you have keytool in you bin folder of java program.

#### Hash code generation

- Open CMD ,use command below
- path for `keytool -exportcert -alias androiddebugkey -keystore path for keystore | path for openssl  sha1 -binary | path for openssl base64`

    ```C:\\Program Files\\Java\\jdk1.6.0_30\\bin>keytool -exportcert -alias androiddebugkey -keystore 
    "C:\\Users\\.android\\debug.keystore" | "C:\\OpenSSL\\bin\\openssl" sha1 -binary |"C:\\OpenSSL\bin\\openssl" base64
    ```

    <p align="center">
      <img alt="KeystreGenerate" src="http://www.androidhive.info/wp-content/uploads/2012/05/android_facebook_generating_key_hash.png?f8a0a3">
    </p>

- Hash code is generated based on keystore password.

    - http://javatechig.com/android/how-to-get-key-hashes-for-android-facebook-app

    - http://www.androidhive.info/2012/03/android-facebook-connect-tutorial/


### Other Security Stuffs

- SSL

    - SSL (Secure Sockets Layer) is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and integral.

- HTPPS=HTTP+SSL

    - https://www.youtube.com/watch?v=JCvPnwpWVUQ

    - https://www.youtube.com/watch?v=SJJmoDZ3il8


- SHA

    - In cryptography, SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function designed by the United States National Security Agency and is a U.S. Federal Information Processing Standard published by the United States NIST. SHA-1 produces a 160-bit (20-byte) hash value known as a message digest. A SHA-1 hash value is typically rendered as a hexadecimal number, 40 digits long.

    - SHA-1 is no longer considered secure against well-funded opponents. In 2005, cryptanalysts found attacks on SHA-1 suggesting that the algorithm might not be secure enough for ongoing use, and since 2010 many organizations have recommended its replacement by SHA-2 or SHA-3. Microsoft, Google and Mozilla have all announced that their respective browsers will stop accepting SHA-1 SSL certificates by 2017.


- Digest

    - Digest access authentication is one of the methods a web server can use to negotiate credentials, such as username or password, with a user's web browser. This can be used to confirm the identity of a user before sending sensitive information, such as online banking transaction history. It applies a hash function to the username and password before sending them over the network.

    - Technically, digest authentication is an application of MD5 cryptographic hashing with usage of nonce values to prevent replay attacks. It uses the HTTP protocol.



- MD5

    - MD5 is an algorithm that is used to verify data integrity through the creation of a 128-bit message digest from data input (which may be a message of any length) that is claimed to be as unique to that specific data as a fingerprint is to the specific individual.
