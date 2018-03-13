package com.ssltest;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESClientServer {
	private Key keyK = null;
	private Cipher enCipher = null;
	private Cipher deCipher = null;
			
	public AESClientServer(String algorithm, String transformation, String keyString){
		
		//Creatng Key object from keyString
		byte[] key;
		try {
			key = keyString.getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // use only first 128 bit
			keyK = new SecretKeySpec(key, algorithm); 
			
			enCipher = Cipher.getInstance(transformation);
			enCipher.init(Cipher.ENCRYPT_MODE, keyK);
			
			deCipher = Cipher.getInstance(transformation);
			deCipher.init(Cipher.DECRYPT_MODE, keyK, new IvParameterSpec(this.enCipher.getIV()));
			
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * 
	 * @param encInFile
	 * @param encOutFile
	 */
	public void encrypt(String encInFile, String encOutFile){

		// Stream - Encrypt to File
		try {
			InputStream is = new FileInputStream(encInFile);
			OutputStream out = new FileOutputStream(encOutFile);
			CipherOutputStream cis = new CipherOutputStream(out, this.enCipher);

			byte[] buffer = new byte[1024];
			int r;
			while ((r = is.read(buffer)) > 0) {
				cis.write(buffer, 0, r);
			}

			cis.close();
			is.close();
			out.close();
			
			System.out.println("Encryption completed successfully");
			
		} catch (Exception e) {
			e.printStackTrace();
		}		
	}

	/**
	 * 
	 * @param decInFile
	 * @param decOutFile
	 */
	public void decrypt(String decInFile, String decOutFile){
		// Stream - Decrypt from file
		try {
			InputStream is = new FileInputStream(decInFile);
			OutputStream out = new FileOutputStream(decOutFile);
			CipherInputStream cis = new CipherInputStream(is, this.deCipher);
			byte[] buffer = new byte[1024];
			int r;
			while ((r = cis.read(buffer)) > 0) {
				out.write(buffer, 0, r);
			}
			cis.close();
			is.close();
			out.close();
			
			System.out.println("Decryption completed successfully");
		} catch (Exception e) {
			e.printStackTrace();
		}		
	}
 
	public static void main(String... argv) throws Exception {
		String encInFile = "src\\resources\\datatoencrypt.txt";
		String encOutFile = "src\\resources\\encrypted.txt";

		String decInFile = "src\\resources\\encrypted.txt";
		String decOutFile = "src\\resources\\decrypted.txt";
		
		//Create Instance
		AESClientServer aesClient = new AESClientServer("AES", "AES/CBC/PKCS5Padding", "abcdkdkjdsdsfdfd12432434323");

		//Encrypt
		aesClient.encrypt(encInFile, encOutFile);

		//Decrypt
		aesClient.decrypt(decInFile, decOutFile);

	}
}