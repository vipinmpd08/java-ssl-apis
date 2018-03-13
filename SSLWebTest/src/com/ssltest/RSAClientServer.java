package com.ssltest;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.*;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import sun.misc.BASE64Decoder;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAClientServer {
	public static KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048, new SecureRandom());
		KeyPair pair = generator.generateKeyPair();

		return pair;
	}

	public static KeyPair getKeyPairFromKeyStore() throws Exception {
		// Generated with:
		// keytool -genkeypair -alias newbigdatatest -storepass changeit
		// -keypass s3cr3t -keyalg RSA -keystore praveenskeystore.jks

		InputStream ins = new FileInputStream(new File(
				"src\\resources\\praveenskeystore.jks"));

		KeyStore keyStore = KeyStore.getInstance("JCEKS");

		// Keystore password
		keyStore.load(ins, "changeit".toCharArray());

		// Key password
		KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(
				"s3cr3t".toCharArray());

		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore
				.getEntry("newbigdatatest", keyPassword);

		java.security.cert.Certificate cert = keyStore
				.getCertificate("newbigdatatest");
		PublicKey publicKey = cert.getPublicKey();
		PrivateKey privateKey = privateKeyEntry.getPrivateKey();

		return new KeyPair(publicKey, privateKey);
	}

	public static String encrypt(String plainText, PublicKey publicKey)
			throws Exception {
		Cipher encryptCipher = Cipher.getInstance("RSA");
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

		byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

		return DatatypeConverter.printBase64Binary(cipherText);
	}

	public static String decrypt(String cipherText, PrivateKey privateKey)
			throws Exception {
		byte[] bytes = DatatypeConverter.parseBase64Binary(cipherText);

		Cipher decriptCipher = Cipher.getInstance("RSA");
		decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

		return new String(decriptCipher.doFinal(bytes), UTF_8);
	}

	public static String sign(String plainText, PrivateKey privateKey)
			throws Exception {
		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(privateKey);
		privateSignature.update(plainText.getBytes(UTF_8));

		byte[] signature = privateSignature.sign();

		return DatatypeConverter.printBase64Binary(signature);
	}

	public static boolean verify(String plainText, String signature,
			PublicKey publicKey) throws Exception {
		Signature publicSignature = Signature.getInstance("SHA256withRSA");
		publicSignature.initVerify(publicKey);
		publicSignature.update(plainText.getBytes(UTF_8));

		byte[] signatureBytes = DatatypeConverter.parseBase64Binary(signature);

		return publicSignature.verify(signatureBytes);
	}

	public static void main(String... argv) throws Exception {
		// First generate a public/private key pair
		// KeyPair pair = generateKeyPair();
		
		//Create KeyPaid from Keystore
		KeyPair pair = getKeyPairFromKeyStore();

		// Our secret message
		String message = "this is the message to me encrypted";

		// Encrypt the message
		String cipherText = encrypt(message, pair.getPublic());

		// Now decrypt it
		String decipheredMessage = decrypt(cipherText, pair.getPrivate());

		System.out.println(decipheredMessage);

		// Let's sign our message
		String signature = sign("praveensigned", pair.getPrivate());

		// Let's check the signature
		boolean isCorrect = verify("praveensigned", signature,
		pair.getPublic());
		System.out.println("Signature correct: " + isCorrect);

		// Streams Example using writer
		CipherOutputStream output = null;
		FileOutputStream fileOutput = null;

		CipherInputStream input = null;
		FileInputStream fileInput = null;
		try {
			fileOutput = new FileOutputStream(
					"src\\resources\\CipherOutput.txt");
			fileInput = new FileInputStream(
					"src\\resources\\CipherOutput.txt");

			Cipher encryptCipher = Cipher.getInstance("RSA");
			encryptCipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
			output = new CipherOutputStream(fileOutput, encryptCipher);

			final PrintWriter pw = new PrintWriter(output);
			pw.println("Add your stream here to see encryption");
			pw.flush();
			pw.close();

			Cipher decriptCipher = Cipher.getInstance("RSA");
			decriptCipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
			input = new CipherInputStream(fileInput, decriptCipher);

			final InputStreamReader r = new InputStreamReader(input);
			final BufferedReader reader = new BufferedReader(r);
			final String line = reader.readLine();
			System.out.println("Line : " + line);

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {

				if (fileInput != null) {
					fileInput.close();
				}
				if (fileOutput != null) {
					fileOutput.flush();
					fileOutput.close();
				}
				if (output != null) {
					output.flush();
					output.close();
				}
				if (input != null) {
					input.close();
				}

			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		// AES Streaming encryption Example using CipherInputStream
		String transformation = "AES/CBC/PKCS5Padding";
		String algorithm = "AES";
		Key keyK = null;
		Cipher cipher = null;
		String keyString = "abcdkdkjdsdsfdfd12432434323"; // Key to be read from
															// config file
		// Stream - Encrypt to File
		try {

			// Creatng Key object from keyString
			byte[] key = keyString.getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // use only first 128 bit
			keyK = new SecretKeySpec(key, algorithm);

			cipher = Cipher.getInstance(transformation);
			cipher.init(Cipher.ENCRYPT_MODE, keyK);

			InputStream is = new FileInputStream(
					"\\src\\resources\\datatoencrypt.txt");
			OutputStream out = new FileOutputStream(
					"\\src\\resources\\encrypted.txt");
			CipherOutputStream cis = new CipherOutputStream(out, cipher);

			byte[] buffer = new byte[1024];
			int r;
			while ((r = is.read(buffer)) > 0) {
				cis.write(buffer, 0, r);
			}

			cis.close();
			is.close();
			out.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out
				.println("File stream datatoencrypt.txt encrypted to encrypt.txt");

		// Stream - Decrypt from file
		try {
			Cipher cipherToDecrypt = Cipher.getInstance(transformation);
			cipherToDecrypt.init(Cipher.DECRYPT_MODE, keyK,
					new IvParameterSpec(cipher.getIV()));

			InputStream is = new FileInputStream(
					"\\src\\resources\\encrypted.txt");
			OutputStream out = new FileOutputStream(
					"\\src\\resources\\decrypted.txt");
			CipherInputStream cis = new CipherInputStream(is, cipherToDecrypt);
			byte[] buffer = new byte[1024];
			int r;
			while ((r = cis.read(buffer)) > 0) {
				out.write(buffer, 0, r);
			}
			cis.close();
			is.close();
			out.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("File stream encrypt.txt decrypted to decrypt.txt");

	}
}