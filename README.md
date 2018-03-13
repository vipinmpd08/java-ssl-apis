# java-ssl-apis
Open source Java examples to do public and private key encryption and message signing.


# RSA Examples using Key Pair

Please view class RSAClientServer.java for RSA encrypt decrypt examples using the following methodologies
- [x] dynamic generated key pair
this will initiate KeyPair using a dynamically generated Key combinations
> KeyPair pair = generateKeyPair();

- [x] using public private keys from a valid keystore
Generate your keystore with a trustedKey entry and use the below approach to call encryption and decryption
> KeyPair pair = getKeyPairFromKeyStore();

keystore updated as below
> keytool -genkeypair -alias datatest -storepass changeit -keypass s3cr3t -keyalg RSA -keystore keystore.jks

- [x] sign() your message and verify() it
also provided one example to sign and verify the message

# AES Encryption of Streamed data

View AESClientServer.java to see the usage of CipherInputStream and CipherOutputStream. Useful for bigdata encryption. 

> 		//Create Instance
		AESClientServer aesClient = new AESClientServer("AES", "AES/CBC/PKCS5Padding", "abcdkdkjdsdsfdfd12432434323");

		//Encrypt
		aesClient.encrypt(encInFile, encOutFile);

		//Decrypt
		aesClient.decrypt(decInFile, decOutFile);