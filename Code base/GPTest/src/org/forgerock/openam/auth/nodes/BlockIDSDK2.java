package org.forgerock.openam.auth.nodes;
/** Created by @author GYANPRAKASH PANDEY on January 20 2021
**  Copyright © 2020 1Kosmos. All rights reserved.
**/


import java.io.BufferedReader;

import java.io.InputStreamReader;
//import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;

import java.time.Instant;
import java.util.Base64;

import java.util.Properties;

import java.util.UUID;

import org.json.JSONException;
import org.json.JSONObject;

import com.onekosmos.BlockIDDecrypt;
import com.onekosmos.EncryptDecryptLogic;



public class BlockIDSDK2  {

	static String my_public_key="";// =
								// "os9skQhJpyJIz7g5xgopwlN3N7eqMR9XMupvIIZf+CkB0V5ADDDdQ0wfA8KqH98NuFch4cIm6qwfuLGwoPCk+A==";
	static String my_private_key;// = "cGB/g7jd/jw1v4z8FDfoeppYQ6y1IJAYzPPkzKkCc4w=";
	static String tenantTag;// = "demo2";
	static String tenantURL;// = "https://demo2-pilot.1kosmos.net";
	static String communityName;// = "default";
	static String licenseKey;// = "c1fe166d-997b-4b4a-81f2-46a02be18b83";
	static String appId;// = "com.bid.jsp.sdk";
	static String server_public_key = "";
	static String server_shared_key = "";
	static String encryptedLicenseKey = "";
	static BlockIDECDSAHelper blockIDECDSAHelper;
	

	public BlockIDSDK2(String tenant,String  tag,String  community) {

		try {
			
			Properties blockidProperties = new Properties();
			blockidProperties.load(BlockIDSDK2.class.getResourceAsStream("blockid.properties"));
			my_public_key = blockidProperties.getProperty("my_public_key");
			my_private_key = blockidProperties.getProperty("my_private_key");
			tenantTag = (tag==null?blockidProperties.getProperty("tenantTag"):tag);
			tenantURL = (tenant==null?blockidProperties.getProperty("tenantURL"):tenant);
			communityName = ( community==null?blockidProperties.getProperty("communityName"):community);
			licenseKey = blockidProperties.getProperty("licenseKey");
			appId = blockidProperties.getProperty("appId");
			
			// reading public key of BlockID server (Admin console)
			
			server_public_key = getBlockIDServerPublicKey();
		//	System.out.println("Public Key:" + server_public_key);

			// Initializing helper class to generate shared key (to be used for
			// Encryption/Decryption)
			blockIDECDSAHelper = new BlockIDECDSAHelper();
			BlockIDDecrypt bd = new BlockIDDecrypt();
			String getSharedKey = bd.generateSharedKey(Base64.getDecoder().decode(my_private_key),
					Base64.getDecoder().decode(server_public_key.getBytes()));
		//	System.out.println("**Shared key generated***" + getSharedKey);
			server_shared_key = getSharedKey;
			
			EncryptDecryptLogic ed = new EncryptDecryptLogic();
			encryptedLicenseKey = ed.encryptPlainTextWithRandomIVNew(licenseKey, server_shared_key);
		//	System.out.println("encryptedLicenseKey:" + encryptedLicenseKey);

		} catch (Exception e) {
			System.out.println("Exception occurred while initialsing BlockIDSDK. Message is:" + e.getMessage());
			e.printStackTrace();
		}

	}



	/**
	 * This method checks for session response for given Session ID.
	 * 
	 * @param sessionID
	 * @return
	 */
	protected String generateMagicLink(String userid, String firstname, String lastname, String email, String proxyHostname, String proxyPort) {

		String requestID = generateRequestID();
		String URL = tenantURL + "/api/r1/acr/community/default/code";
		URL obj;
		try {
			
			Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHostname, Integer.parseInt(proxyPort)));
			
			obj = new URL(URL);
			HttpURLConnection con = (HttpURLConnection) obj.openConnection(proxy);
			con.setRequestMethod("PUT");
			con.setRequestProperty("Accept", "*/*");
			con.setRequestProperty("Content-Type", "application/json");
			con.setRequestProperty("X-TenantTag", tenantTag);
			con.setRequestProperty("publicKey", my_public_key);
			con.setRequestProperty("licensekey", encryptedLicenseKey);
			con.setRequestProperty("requestid", requestID);
			con.setDoOutput(true);
			String data = generateUserdata(userid, firstname, lastname, email);
			

			JSONObject jsonObject = new JSONObject();
			

				jsonObject.put("data", data);
				
				String jsonInputString = jsonObject.toString();
			

			con.getOutputStream().write(jsonInputString.getBytes("utf-8"));
			
			try(BufferedReader br = new BufferedReader(
					  new InputStreamReader(con.getInputStream(), "utf-8"))) {
					    StringBuilder response = new StringBuilder();
					    String responseLine = null;
					    while ((responseLine = br.readLine()) != null) {
					        response.append(responseLine.trim());
					    }
					    System.out.println("response" +response.toString());
					}
			//BufferedReader iny = new BufferedReader(new OutputStreamReader(con.getOutputStream().write(data.getBytes());));
			/*
			 * try(OutputStream os = con.getOutputStream()) { byte[] input =
			 * data.getBytes("utf-8"); os.write(input, 0, input.length); }
			 */
			
			  System.out.println("**Magic link API called for:" + userid + "\n");
			//  con.disconnect();
			 
			 

		} catch (Exception e) {

			System.out.println("Exception occurred while generating Magic link. Message is:" + e.getMessage());
			e.printStackTrace();
		}

		return null;

	}

	/**
	 * This method fetches publicKey of BlockID server
	 * 
	 * @return
	 */
	public static String getBlockIDServerPublicKey() {

		String URL = tenantURL + "/api/r1/community/default/publickeys";
		URL obj;
		try {
			//obj = new URL(URL);
			//HttpURLConnection con = (HttpURLConnection) obj.openConnection();
			
			//Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, Integer.parseInt(proxyPort)));
			
			obj = new URL(URL);
			HttpURLConnection con = (HttpURLConnection) obj.openConnection();
			
			
			con.setRequestMethod("GET");
			con.setRequestProperty("Accept", "*/*");
			con.setRequestProperty("X-TenantTag", tenantTag);
			con.setDoOutput(true);
			BufferedReader iny = new BufferedReader(new InputStreamReader(con.getInputStream()));
			String output;
			StringBuffer response = new StringBuffer();

			while ((output = iny.readLine()) != null) {
				response.append(output);
			}
			iny.close();
			JSONObject jsonObject = new JSONObject(response.toString());
		//	System.out.println(jsonObject.get("publicKey"));

			//System.out.println(response.toString());
			return jsonObject.get("publicKey").toString();

		} catch (Exception e) {
			System.out.println(
					"Exception occurred while fetching public key of BlockID server. Message is:" + e.getMessage());
			e.printStackTrace();
		}

		return "NO_VALUE";
	}

	/**
	 * This method generates requestID to be passed in header to admin console APIs.
	 * 
	 * @return
	 */
	private String generateRequestID() {

		String requestID = "";

		Instant instant = Instant.now();
		long timeStampSeconds = instant.getEpochSecond();

		UUID uuid = UUID.randomUUID();

		String appID = appId;

		JSONObject jsonObject = new JSONObject();
		try {

			jsonObject.put("ts", timeStampSeconds);
			jsonObject.put("appId", appID);
			jsonObject.put("uuid", uuid);

			String plainRequestID = jsonObject.toString();

			EncryptDecryptLogic ed = new EncryptDecryptLogic();
			String encryptedRequestID = ed.encryptPlainTextWithRandomIVNew(plainRequestID, server_shared_key);
	
			return encryptedRequestID;
		} catch (Exception e) {
			System.out.println("Exception occurred while generating requestID. Message is:" + e.getMessage());
			e.printStackTrace();
		}
		return requestID;

	}
	
	/**
	 * This method generates requestID to be passed in header to admin console APIs.
	 * 
	 * @return
	 */
	private String generateUserdata(String userid, String firstname, String lastname, String email) {


		JSONObject jsonObject = new JSONObject();
		try {

			jsonObject.put("userId", userid);
			jsonObject.put("firstname", firstname);
			jsonObject.put("lastname", lastname);
			jsonObject.put("email", email);
			jsonObject.put("createdBy", "BlockID-Sales");
			jsonObject.put("createdbyemail", email);

			String plainRequestID = jsonObject.toString();

			EncryptDecryptLogic ed = new EncryptDecryptLogic();
			String encryptedRequestID = ed.encryptPlainTextWithRandomIVNew(plainRequestID, server_shared_key);
	
			return encryptedRequestID;
		} catch (Exception e) {
			System.out.println("Exception occurred while ecrypting userdata. Message is:" + e.getMessage());
			e.printStackTrace();
		}
		return "";

	}
	
	
	/**
	 * This method sends push notification for the given user ID.
	 * 
	 * @param userID
	 * @return
	 */
	protected String sendPushNotification(String userid, String sessionID) {

		String requestID = generateRequestID();
		String URL = tenantURL + "/api/v3/rest/default/pushnotification";
		URL obj;
		try {
			obj = new URL(URL);
			HttpURLConnection con = (HttpURLConnection) obj.openConnection();
			con.setRequestMethod("POST");
			con.setRequestProperty("Accept", "*/*");
			con.setRequestProperty("Content-Type", "application/json");
			con.setRequestProperty("X-TenantTag", tenantTag);
			con.setRequestProperty("publickey", my_public_key);
			con.setRequestProperty("licensekey", encryptedLicenseKey);
			con.setRequestProperty("requestid", requestID);
			con.setDoOutput(true);
			
			

			JSONObject jsonObject = new JSONObject();
			
				JSONObject pushObject = new JSONObject();
				pushObject.put("session", sessionID);
				pushObject.put("authtype", "Face");
				pushObject.put("scopes", "windows");
				pushObject.put("creds", "");
				pushObject.put("publicKey", my_public_key);
				System.out.println("Environment:" + tenantURL + ":"+tenantTag+":"+communityName);
				pushObject.put("api", tenantURL);
				pushObject.put("tag", tenantTag);
				pushObject.put("community", communityName);
				pushObject.put("authPage", "blockid://authenticate?method=scep");				
				jsonObject.put("userid", userid);
				//jsonObject.put("data", Base64.getEncoder().encodeToString(pushObject.toString().getBytes()));
				
				   Base64.Encoder encoder = Base64.getEncoder();  
				   jsonObject.put("data",  encoder.encodeToString(pushObject.toString().getBytes()));
				  // jsonObject.put("data",  pushObject.toString());
				  
				System.out.println("JSON being sent=>:" + jsonObject.toString() + "\n");
				//String jsonInputString = generatePushPayload(encoder.encodeToString(jsonObject.toString().getBytes()));
				String jsonInputString = generatePushPayload(jsonObject.toString());
				JSONObject jsonDataObject = new JSONObject();
				jsonDataObject.put("data", jsonInputString);
				jsonDataObject.put("publicKey", my_public_key);
				 System.out.println("Data being sent:" + jsonDataObject.toString() + "\n");
				 
				 con.getOutputStream().write(jsonDataObject.toString().getBytes("utf-8"));
			//con.getOutputStream().write(jsonInputString.getBytes("utf-8"));
			
			try(BufferedReader br = new BufferedReader(
					  new InputStreamReader(con.getInputStream(), "utf-8"))) {
					    StringBuilder response = new StringBuilder();
					    String responseLine = null;
					    while ((responseLine = br.readLine()) != null) {
					        response.append(responseLine.trim());
					    }
					    System.out.println("response" +response.toString());
					}
			//BufferedReader iny = new BufferedReader(new OutputStreamReader(con.getOutputStream().write(data.getBytes());));
			/*
			 * try(OutputStream os = con.getOutputStream()) { byte[] input =
			 * data.getBytes("utf-8"); os.write(input, 0, input.length); }
			 */
			
			  System.out.println("*Push notification API called for:" + userid + "\n");
			//  con.disconnect();
			 int count=0;
			  while(true) {
				  String resp =checkAuthSession(sessionID);
				  System.out.println("*Polling for session ID:" + sessionID + " response:" + resp);
				  if(resp==null) {
					  count++;
					  Thread.sleep(1000);
						  if(count>59) {
							  System.out.println("*No Response receiveed for session ID:" + sessionID );
							  return "failure";
						  
						  }
					  continue;
					  } else {
						  System.out.println("*Response receiveed for session ID:" + sessionID + " response:" + resp);
						  return "success";
					}
			 
			  }

		} catch (Exception e) {

			System.out.println("Exception occurred while generating Magic link. Message is:" + e.getMessage());
			e.printStackTrace();
		}

		return "failure";

	}

	
	/**
	 * This method generates encrypteduser data to be passed in header to admin console APIs.
	 * 
	 * @return
	 */
	private String generatePushPayload(String data) {


		
		try {

			
			

			String plainRequestID = data;

			EncryptDecryptLogic ed = new EncryptDecryptLogic();
			String encryptedRequestID = ed.encryptPlainTextWithRandomIVNew(plainRequestID, server_shared_key);
	
			return encryptedRequestID;
		} catch (Exception e) {
			System.out.println("Exception occurred while ecrypting userdata. Message is:" + e.getMessage());
			e.printStackTrace();
		}
		return "";

	}
	
	/**
	 * This method checks for session response for given Session ID.
	 * 
	 * @param sessionID
	 * @return
	 */
	private String checkAuthSession(String sessionID) {

		String requestID = generateRequestID();
		String URL = tenantURL + "/api/r1/community/default/session/" + sessionID + "/response";
		URL obj;
		try {
			obj = new URL(URL);
			HttpURLConnection con = (HttpURLConnection) obj.openConnection();
			con.setRequestMethod("GET");
			con.setRequestProperty("Accept", "*/*");
			con.setRequestProperty("Content-Type", "application/json");
			con.setRequestProperty("X-TenantTag", tenantTag);
			con.setRequestProperty("publicKey", my_public_key);
			con.setRequestProperty("licensekey", encryptedLicenseKey);
			con.setRequestProperty("requestid", requestID);
			con.setDoOutput(true);
			BufferedReader iny = new BufferedReader(new InputStreamReader(con.getInputStream()));
			String output;
			StringBuffer response = new StringBuffer();

			while ((output = iny.readLine()) != null) {
				response.append(output);
			}

			iny.close();
			if (response == null || response.length() < 1) {
				return null;
			}
			System.out.println("Response from BlockID server:" + response.toString());
		//	return response.toString(); uncomment for Jef
			
			  JSONObject jsonObject = new JSONObject(response.toString());
			  
			  System.out.println(response.toString());
			  
			  String getSharedKey =
			  blockIDECDSAHelper.generateSharedKey(Base64.getDecoder().decode(
			  my_private_key),
			  Base64.getDecoder().decode(jsonObject.get("publicKey").toString().getBytes())
			  );
			  
			  String decryptedData =
			  blockIDECDSAHelper.decryptCipherTextWithRandomIVNew(jsonObject.get("data").toString(),getSharedKey);//ed.decryptCipherTextWithRandomIV(jsonObject.get("data"),
			
			  System.out.println("**Data obtained is:***" +  decryptedData);
			  
			  return decryptedData;
			 

		} catch (Exception e) {

			System.out.println("Exception occurred while checking session. Message is:" + e.getMessage());
			e.printStackTrace();
		}

		return null;

	}
	
	
	/**
	 * This method checks for session response for given Session ID.
	 * 
	 * @param sessionID
	 * @return
	 */
	protected String extractUsername(String BlockIDAuthnString) {

		 String decryptedData = null;
		 JSONObject jsonObject;
		try {
			jsonObject = new JSONObject(BlockIDAuthnString);
		
		   System.out.println("Inside extractUsername:"+BlockIDAuthnString);
		  
		  String getSharedKey =
		  blockIDECDSAHelper.generateSharedKey(Base64.getDecoder().decode(
		  my_private_key),
		  Base64.getDecoder().decode(jsonObject.get("publicKey").toString().getBytes())
		  );
		  System.out.println("Public Key:" + my_private_key);
		  System.out.println("Public Key:" + jsonObject.get("publicKey"));
		  System.out.println("Shared Key:" + getSharedKey);
		  System.out.println("Data:" + jsonObject.get("data"));
		  
		  decryptedData =
		  blockIDECDSAHelper.decryptCipherTextWithRandomIVNew(jsonObject.get("data").toString(),getSharedKey);
		  System.out.println("**Data obtained is:***" +  decryptedData);
		  JSONObject userObject = new JSONObject(decryptedData);
		  return userObject.getString("userid");
		  
		  
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		  
		return decryptedData;

	}


}
