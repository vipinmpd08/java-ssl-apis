package com.ssltest;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.net.URL;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.util.logging.Logger;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509KeyManager;

public class HTTPSFileReader {

	private static final Logger logger = Logger.getLogger(HTTPSFileReader.class
			.getName());
	private static final String LINE_BREAKER = System
			.getProperty("line.separator");

	private static final String CERTIFACATE_FILE = "src\\resources\\keystore.jks";
	private static final String CERTIFACATE_PASS = "changeit";
	private static final String CERTIFACATE_ALIAS = "alias";
	private static final String TARGET_URL = "https://localhost:8443/basic/mp3/InfiniteLoveARRahman.mp3";

	public static void main(String a[]) {
		String targetURL = TARGET_URL;
		URL url;
		HttpsURLConnection connection = null;
		BufferedReader bufferedReader = null;
		InputStream is = null;

		try {

			logger.info("Disabling Certificate Name validation as it is self signed");
			javax.net.ssl.HttpsURLConnection
					.setDefaultHostnameVerifier(new javax.net.ssl.HostnameVerifier() {

						public boolean verify(String hostname,
								javax.net.ssl.SSLSession sslSession) {
							if (hostname.equals("localhost")) {
								return true;
							}
							return false;
						}
					});

			// Create connection
			url = new URL(targetURL);

			connection = (HttpsURLConnection) url.openConnection();

			logger.info("Connection opened");

			connection.setRequestMethod("GET");

			SSLSocketFactory sslSocketFactory = getFactory(new File(
					CERTIFACATE_FILE), CERTIFACATE_PASS, CERTIFACATE_ALIAS);

			logger.info("SSL Object created from the given keytore");

			connection.setSSLSocketFactory(sslSocketFactory);

			logger.info("SSL Authenticated, Reading started");

			// Process response
			is = connection.getInputStream();

			bufferedReader = new BufferedReader(new InputStreamReader(is));
			String line;
			StringBuffer lines = new StringBuffer();

			logger.info("response from " + targetURL);
			while ((line = bufferedReader.readLine()) != null) {
				lines.append(line);
				logger.info(line);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static SSLSocketFactory getFactory(File pKeyFile,
			String pKeyPassword, String certAlias) throws Exception {
		KeyManagerFactory keyManagerFactory = KeyManagerFactory
				.getInstance("SunX509");
		KeyStore keyStore = KeyStore.getInstance("JKS");

		InputStream keyInput = new FileInputStream(pKeyFile);
		keyStore.load(keyInput, pKeyPassword.toCharArray());
		keyInput.close();
		keyManagerFactory.init(keyStore, pKeyPassword.toCharArray());

		// Replace the original KeyManagers with the AliasForcingKeyManager
		KeyManager[] kms = keyManagerFactory.getKeyManagers();
		for (int i = 0; i < kms.length; i++) {
			if (kms[i] instanceof X509KeyManager) {
				kms[i] = new AliasForcingKeyManager((X509KeyManager) kms[i],
						certAlias);
			}
		}

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(kms, null, null);
		return context.getSocketFactory();
	}

	/*
	 * This wrapper class overwrites the default behavior of a X509KeyManager
	 * and always render a specific certificate whose alias matches that
	 * provided in the constructor
	 */
	private static class AliasForcingKeyManager implements X509KeyManager {

		X509KeyManager baseKM = null;
		String alias = null;

		public AliasForcingKeyManager(X509KeyManager keyManager, String alias) {
			baseKM = keyManager;
			this.alias = alias;
		}

		/*
		 * Always render the specific alias provided in the constructor
		 */
		public String chooseClientAlias(String[] keyType, Principal[] issuers,
				Socket socket) {
			return alias;
		}

		public String chooseServerAlias(String keyType, Principal[] issuers,
				Socket socket) {
			return baseKM.chooseServerAlias(keyType, issuers, socket);
		}

		public java.security.cert.X509Certificate[] getCertificateChain(
				String alias) {
			return baseKM.getCertificateChain(alias);
		}

		public String[] getClientAliases(String keyType, Principal[] issuers) {
			return baseKM.getClientAliases(keyType, issuers);
		}

		public PrivateKey getPrivateKey(String alias) {
			return baseKM.getPrivateKey(alias);
		}

		public String[] getServerAliases(String keyType, Principal[] issuers) {
			return baseKM.getServerAliases(keyType, issuers);
		}
	}

}
