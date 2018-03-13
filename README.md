# java-ssl-apis
Open source Java examples to do public and private key encryption and message signing.


# RSA Examples using Key Pair

Please view class RSAClientServer.java for RSA encrypt decrypt examples using the following methodologies
- [x] dynamic generated key pair - this will initiate KeyPair using a dynamically generated Key combinations
> KeyPair pair = generateKeyPair();

- [x] using public private keys from a valid keystore - Generate your keystore with a trustedKey entry and use the below approach to call encryption and decryption
> KeyPair pair = getKeyPairFromKeyStore();

keystore updated as below
> keytool -genkeypair -alias datatest -storepass changeit -keypass s3cr3t -keyalg RSA -keystore keystore.jks

- [x] sign() your message and verify() it - also provided one example to sign and verify the message
> // Let's sign our message

> String signature = sign("mesigned", pair.getPrivate());

> // Let's check the signature

> boolean isCorrect = verify("mesigned", signature,
		
# AES Encryption of Streamed data

View AESClientServer.java to see the usage of CipherInputStream and CipherOutputStream. Useful for bigdata encryption. 	
> //Create Instance

> AESClientServer aesClient = new AESClientServer("AES", "AES/CBC/PKCS5Padding", "abcdkdkjdsdsfdfd12432434323");

> //Encrypt

> aesClient.encrypt(encInFile, encOutFile);

> //Decrypt

> aesClient.decrypt(decInFile, decOutFile);


# HTTPS example using SSL and X509 certs 

first step is to create a private key (self signed in this example), server is hosted in HTTPS and client is trying to access a file through HTTPS.
To make this work, we have to import server's public key as a trustedCertEntry in the client keystore.

> is = connection.getInputStream();

> SSLSocketFactory sslSocketFactory = getFactory(new File(CERTIFACATE_FILE), CERTIFACATE_PASS, CERTIFACATE_ALIAS);

> connection.setSSLSocketFactory(sslSocketFactory);

> is = connection.getInputStream();

