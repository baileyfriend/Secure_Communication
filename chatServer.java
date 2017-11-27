/*****************************************
Madison Brooks and Bailey Freund
CIS 457-20
Lab Project 4 - Server
-------------Part One---------------------
 Multiple client connections	          10 -- DONE
  Broadcast message (to all clients)	  15 -- DONE
  Individual message	                  10 -- DONE
  Client list	                          5 -- DONE
 Admin functions	                      5 -- DONE
-------------Part Two---------------------
Randomly generate symmetric key	            5
Encrypt symmetric key with RSA pub key	    10
Decrypt symmetric key with RSA private key  10
Properly encrypting all chat messages	    10
Properly decrypting all chat messages  	    10



Exception in thread "Thread-0" java.lang.ArrayIndexOutOfBoundsException: 1
	at chatServer.getDestination(chatServer.java:58)
	at chatServer$ChatServerThread.run(chatServer.java:158)

******************************************/  

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.io.FileOutputStream;
import java.io.File;
import java.io.DataOutputStream;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Set;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import javax.xml.bind.DatatypeConverter;



class chatServer{
    private PrivateKey privKey;
    private PublicKey pubKey; //server sends the public key to all users
    
    //Code provided in documentation
	public chatServer(){
		privKey=null;
		pubKey=null;
	}
	//Code provided in documentation
	public void setPrivateKey(String filename){
		try{
			File f = new File(filename);
			FileInputStream fs = new FileInputStream(f);
			byte[] keybytes = new byte[(int)f.length()];
			fs.read(keybytes);
			fs.close();
			PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(keybytes);
			KeyFactory rsafactory = KeyFactory.getInstance("RSA");
			privKey = rsafactory.generatePrivate(keyspec);
		}catch(Exception e){
			System.out.println("Private Key Exception");
			e.printStackTrace(System.out);
			System.exit(1);
		}
    }
    //Code provided in documentation
    public void setPublicKey(String filename){
		try{
			File f = new File(filename);
			FileInputStream fs = new FileInputStream(f);
			byte[] keybytes = new byte[(int)f.length()];
			fs.read(keybytes);
			fs.close();
			X509EncodedKeySpec keyspec = new X509EncodedKeySpec(keybytes);
			KeyFactory rsafactory = KeyFactory.getInstance("RSA");
			pubKey = rsafactory.generatePublic(keyspec);
		}catch(Exception e){
			System.out.println("Public Key Exception");
			System.exit(1);
		}
    }
	//Code provided in documentation
	public SecretKey generateAESKey(){
		try{
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			SecretKey secKey = keyGen.generateKey();
			return secKey;
		}catch(Exception e){
			System.out.println("Key Generation Exception");
			System.exit(1);
			return null;
		}
    }
    //Code provided in documentation
    public byte[] RSAEncrypt(byte[] plaintext){
		try{
			Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
			c.init(Cipher.ENCRYPT_MODE,pubKey);
			byte[] ciphertext=c.doFinal(plaintext);
			return ciphertext;
		}catch(Exception e){
			System.out.println("RSA Encrypt Exception");
			System.exit(1);
			return null;
		}
    }
    //Code provided in documentation
    public byte[] RSADecrypt(byte[] ciphertext){
		try{
			Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
			c.init(Cipher.DECRYPT_MODE,privKey);
			byte[] plaintext=c.doFinal(ciphertext);
			return plaintext;
		}catch(Exception e){
			System.out.println("RSA Decrypt Exception");
			System.exit(1);
			return null;
		}
    }
    //Code provided in documentation
    public byte[] decrypt(byte[] ciphertext, SecretKey secKey, IvParameterSpec iv){
		try{
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			c.init(Cipher.DECRYPT_MODE,secKey,iv);
			byte[] plaintext = c.doFinal(ciphertext);
			return plaintext;
		}catch(Exception e){
			System.out.println("AES Decrypt Exception");
			System.exit(1);
			return null;
		}
    }
    //Code provided in documentation
    public byte[] encrypt(byte[] plaintext, SecretKey secKey, IvParameterSpec iv){
		try{
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			c.init(Cipher.ENCRYPT_MODE,secKey,iv);
			byte[] ciphertext = c.doFinal(plaintext);
			return ciphertext;
		}catch(Exception e){
			System.out.println("AES Encrypt Exception");
			System.exit(1);
			return null;
		}
    } 
    
	public static ConcurrentHashMap<Integer, SocketChannel> clientMap = new ConcurrentHashMap<Integer, SocketChannel>();

	public static SocketChannel getFromClientMap(int clientNum){ //Gets the socketChannel from the map
		return clientMap.get(clientNum);
	} 
	
	public void putIntoClientMap(int clientNum, SocketChannel sc){ // put key-value pair into map
		clientMap.put(clientNum, sc);
	}

	public static String readBufferIntoString(ByteBuffer buf){
		byte[] bytes;
		bytes = buf.array();
		return new String(bytes);
	}

	public static int getDestination(String msg){
		String [] splitMsg = msg.split("\\|");
		String destStr = splitMsg[0];
		String message = splitMsg[1];
		if(destStr.toLowerCase().equals("all")){
			sendToAll(message);
			return -1;
		} else if(destStr.toLowerCase().contains("kick")){
			int userToKick = Integer.parseInt( Character.toString(destStr.charAt(4)) );
			kickUser(userToKick);
			return -1;
		} else {
			return Integer.parseInt(destStr);
		}
	}

	public static void sendToAll(String msg){
		for(ConcurrentHashMap.Entry<Integer, SocketChannel> entry: clientMap.entrySet()){
			SocketChannel channel = entry.getValue();
			try{
				channel.write(ByteBuffer.wrap(msg.getBytes()));
			} catch(Exception exception){
				System.out.println("Caught error while sending message to all: " + exception);
			}
			
		}
	}

	public static void kickUser(int user){
		System.out.println("Kicking user: " + user);
		SocketChannel channel = clientMap.get(user);
		String kickUserString = "123456789GOODBYE987654321";
		try{
			channel.write(ByteBuffer.wrap(kickUserString.getBytes()));
		} catch(Exception exception){
			System.out.println("Caught error while kicking user: " + exception);
		}
		clientMap.remove(user);
		return;
	}

	public static ByteBuffer getMessage(String msg){
		String [] splitMsg = msg.split("\\|");
		String msgStr = splitMsg[1];
		return ByteBuffer.wrap(msgStr.getBytes());
	}

	public ByteBuffer getListOfConnectedClients(){
		Set<Integer> setOfClients = clientMap.keySet();
		System.out.println("These are the connected clients' names: " + setOfClients.toString());
		return ByteBuffer.wrap(setOfClients.toString().getBytes());
	}
	
	public String getStringOfClients(){
		Set<Integer> setOfClients = clientMap.keySet();
		return setOfClients.toString();	
	}

    public static void main(String args[]){
		chatServer server = new chatServer();
		
		server.setPrivateKey("RSApriv.der"); //making the private key using RSA
		server.setPublicKey("RSApub.der");   //making the public key based on the private key
		
		SecretKey s = server.generateAESKey();
		byte encryptedsecret[] = server.RSAEncrypt(s.getEncoded());
		SecureRandom r = new SecureRandom();
		byte ivbytes[] = new byte[16];
		r.nextBytes(ivbytes);
		IvParameterSpec iv = new IvParameterSpec(ivbytes);
		
		String plaintext = "This is a test string to encrypt";
		byte ciphertext[] = server.encrypt(plaintext.getBytes(),s,iv);
		
		System.out.printf("CipherText: %s%n",DatatypeConverter.printHexBinary(ciphertext));
		byte decryptedsecret[] = server.RSADecrypt(encryptedsecret);
		
		SecretKey ds = new SecretKeySpec(decryptedsecret,"AES");
		byte decryptedplaintext[] = server.decrypt(ciphertext,ds,iv);
		
		String dpt = new String(decryptedplaintext);
		System.out.printf("PlainText: %s%n",dpt);
		
		
		try{
				Boolean portNotValid = false;
		        Console cons = System.console();
		       	int portInt=9876; 
				System.out.println("This server is port number "+portInt);
		        ServerSocketChannel c = ServerSocketChannel.open();	//Open ServerSocketChannel
		        c.bind(new InetSocketAddress(portInt));
		        int clientNum = 0;
		        while(true){
			   		SocketChannel sc = c.accept(); // get new channel for each new client that connects to our server
					server.putIntoClientMap(clientNum, sc); //number of the client mapped with the socket channel.
					System.out.println("Put client " + clientNum + " into map " + clientMap.toString()); //the toString does not work?
					ChatServerThread t = server.new ChatServerThread(sc);
					//TODO: a list of threads - soccet channels to keep track of clients
					//TODO: print a list of available clients
					clientNum++;
					t.start();
				}

		 }catch(IOException e){
		        System.out.println("Got an IO exception");
		 }
	
}
 

class ChatServerThread extends Thread{
	SocketChannel sourceSocketChannel;
	ChatServerThread(SocketChannel channel){
	    sourceSocketChannel = channel;
	}
	public void run(){ //acts as the main method for the new thread
	    try{
			System.out.println("A client has connected");

			//Send the list of the connected clients whenever a new client connects
			ByteBuffer listOfConnectedClients = getListOfConnectedClients();
			sourceSocketChannel.write( listOfConnectedClients );
			System.out.println("Sent client list");
			
			byte [] pkey = pubKey.getEncoded();
			//TODO how to turn the public key into a byte buffer??
			ByteBuffer privateKeyy = pubKey.getBytes();
			sourceSocketChannel.write(privateKeyy);
			System.out.println("Sent public key");
			
			ByteBuffer encryptedKey = ByteBuffer.allocate(10000);
			//TODO decrypt this buffer with the private key to get the secret/symetric key
			
			System.out.println("___________________");
			while(true){
				// Read message from client
				ByteBuffer buffer = ByteBuffer.allocate(10000);
				sourceSocketChannel.read(buffer);
				String msgFromClient = readBufferIntoString(buffer);
				System.out.println("Got message from client: " + msgFromClient);

				// Get the destination from the message
				int destinationInt = getDestination(msgFromClient);
				String clientmap = getStringOfClients();
				if(destinationInt != -1){ // -1 means that there was not a specific destination
					String destinationS = String.valueOf(destinationInt);
					if(!clientmap.contains(destinationS)){ //this thread is no longer in the client list 
						System.exit(0); //so it should not be a thread anymore..
					}
				
					System.out.println("Successfully got the destination from the message - sending to: " + destinationInt);
					//TODO decrypt the message with the symetic key given by the client
					
					// Instantiate the connection to the destination - use clientMap to do this
					SocketChannel destinationSocketChannel = getFromClientMap(destinationInt);
				
					// Get the actual message to be sent to the destination
					ByteBuffer msgToSend = getMessage(msgFromClient);
					System.out.println("Sending message to client: "  + msgToSend);

					// Send the message to the destination
					destinationSocketChannel.write(msgToSend);
					System.out.println("**************************************\n");
			}
		}
		
	    }catch(IOException e){
			System.out.println("Got an Exception: " + e);
	    }

	}
    }
}
