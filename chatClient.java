/*****************************************
Madison Brooks and Bailey Freund
CIS 457-20
Lab Project 4  - Client
-------------Part One---------------------
 Multiple client connections	          10 -- DONE
  Broadcast message (to all clients)	  15 -- DONE
  Individual message	                  10 -- DONE
  Client list	                          5 -- DONE
 Admin functions	                      5 -- DONE
-------------Part Two---------------------
Randomly generate symmetric key	            5  -- DONE
Encrypt symmetric key with RSA pub key	    10
Decrypt symmetric key with RSA private key  10
Properly encrypting all chat messages	    10
Properly decrypting all chat messages  	    10
******************************************/

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.Paths;
import java.util.List;
import java.util.Objects;
import java.lang.Math.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;


class chatClient{
	public String kickUserString = "123456789GOODBYE987654321";
	//private PrivateKey privKey; only the server knows what this is 
	private PublicKey pubKey;
	public SecretKey symKey;
	
    
    public chatClient(){
    	//privKey=null;
		pubKey=null;
		symKey = this.generateAESKey(); //making the Symetric key
	}

	public SecretKey getSymKey(){
		System.out.println("Symmetric key is: " + Base64.getEncoder().encodeToString( this.symKey.getEncoded() ) );
		return this.symKey;
	}

	public void setPubKey(PublicKey pubKey){
		this.pubKey = pubKey;
	}

	public PublicKey getPubKey(){
		//System.out.println("The public key is: " + Base64.getEncoder().encodeToString( this.pubKey.getEncoded() ) );
		return this.pubKey;
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
    public byte[] RSAEncrypt(byte[] plaintext){ //needed to encrypt with the public key, the new secret key
		try{
			System.out.println("length of sym key in rsadecrpyt: " + plaintext.length);
			Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
			c.init(Cipher.ENCRYPT_MODE,getPubKey());
			byte[] ciphertext=c.doFinal(plaintext);
			System.out.printf("CipherText: " + ciphertext.length);
			return ciphertext;
		}catch(Exception e){
			System.out.println("RSA Encrypt Exception: " + e);
			System.exit(1);
			return null;
		}
    }

    //Code provided in documentation
    //the Symetric method for encrypting 
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
      

      /*
        Checks if valid ip
        @return True if string is a valid ip, else false
      */
    public boolean isValidIP(String ip){
      	try{
      	    if(ip == null || ip.isEmpty()){
      			return false;
      	    }

      	    String[] ipArr = ip.split("\\.");
      	    if( ipArr.length != 4 ){
      			return false;
      	    }

      	    for(String numStr : ipArr){
      		int num = Integer.parseInt(numStr);
      		if(num < 0 || num > 255){
      		    return false;
      		}
      	    }

      	    if(ip.endsWith(".")){
      			return false;
      	    }

      	    return true;

      	} catch(NumberFormatException e){
      	    return false; //means it wasn't a number
      	}
	  }
	  
public static String readBufferIntoString(ByteBuffer buf){
		byte[] bytes;
		bytes = buf.array();
		return new String(bytes);
	}

	public static ByteBuffer readKeyIntoBuffer(PublicKey key){
		return ByteBuffer.wrap(key.getEncoded());
	}

	public static PublicKey readBufferIntoPubKey(ByteBuffer buf){
		//byte[] arr = new byte[buf.remaining()];
		try{
			byte[] keyArr = buf.array();
			X509EncodedKeySpec keyspec = new X509EncodedKeySpec(keyArr);
			KeyFactory rsafactory = KeyFactory.getInstance("RSA");
			PublicKey puKey = rsafactory.generatePublic(keyspec);
			return puKey;
		} catch(Exception e){
			System.out.println("Got Exception when reading buf into pubkey: " + e);
			System.exit(1);
			return null;
		}
	}
	public byte[] getCorrectSizeCiphertext(ByteBuffer buf){
		int size = buf.position();
		buf.flip();
		byte[] result = new byte[size];
		for(int i = 0; i<size; i++){
			result[i] = buf.get(i);
		}
		return result;
	}
	public byte[] decrypt(byte[] ciphertext, SecretKey secKey, IvParameterSpec iv){
		try{
			//ciphertext = removeEmptyFromArray(ciphertext);
			System.out.println("Symmetric key is: " + Base64.getEncoder().encodeToString( secKey.getEncoded() ) );
			System.out.printf("CipherText: %s%n",DatatypeConverter.printHexBinary(ciphertext) + '\n'); //coded message to be sent
			System.out.println("here0, ciphertext is this big: " + ciphertext.length);
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			System.out.println("here1");
			c.init(Cipher.DECRYPT_MODE,secKey,iv);
			System.out.println("here2");
			byte[] plaintext = c.doFinal(ciphertext);
			System.out.println("here3");
			return plaintext;
		}catch(Exception e){
			System.out.println("AES Decrypt Exception " + e);
			System.exit(1);
			return null;
		}
    }

	// public List<Object> generateIV(){
	// 	SecureRandom r = new SecureRandom();
	// 	byte ivbytes[] = new byte[16];
	// 	r.nextBytes(ivbytes);
	// 	IvParameterSpec iv = new IvParameterSpec(ivbytes);
	// 	Object[] result = new Object[2];
	// 	// List<Object> arr = new ArrayList <Object>();
	// 	arr.add(iv);
	// 	arr.add(ivbytes);
	// 	// result[0] = iv;
	// 	// result[1] = ivbytes;
	// 	return arr;
	// }

      public static void main(String args[]){
      	chatClient client = new chatClient();
      	try{

      	    //get input
      	    Console cons = System.console();
      	    String ipStr = "127.0.0.1"; // Default ip address
			// @TODO uncomment this section - commented for testing
			boolean valid = false;
			  while(valid == false){ 
          		ipStr = cons.readLine("Enter target IP address: ");
              valid = client.isValidIP(ipStr.trim());
          		if(!valid){
          		    System.out.println("IP address " + ipStr + " is not valid.");
          		    continue;
          		} else{
          		    valid = true;
          		}
			  }

			int portInt=9876; //declaring portInt so the code works
			  
			System.out.println("Now using port number "+portInt); //end of checking port number
			InetSocketAddress insa = new InetSocketAddress(ipStr, portInt);
			SocketChannel sc = SocketChannel.open();
			sc.connect(insa);

			ChatClientRecieveThread receiveThread = client.new ChatClientRecieveThread(sc);
			ChatClientSendThread sendThread = client.new ChatClientSendThread(sc);
			
			ByteBuffer publicKeyBuf = ByteBuffer.allocate(10000);
			sc.read(publicKeyBuf);
			System.out.println("Client has the public key."); //TODO fix this sending on the server side
			PublicKey pubKey = readBufferIntoPubKey(publicKeyBuf);
			client.setPubKey(pubKey);
			System.out.println("The public key is: " + Base64.getEncoder().encodeToString( client.pubKey.getEncoded() ) );

			SecretKey theSymKey = client.getSymKey();
			System.out.println("Sending symmetric key of length: " + theSymKey.getEncoded().length );
			byte encryptedSymKey[] = client.RSAEncrypt(theSymKey.getEncoded());
			//System.out.println("Encrypted Secret: " + Arrays.toString(encryptedSymKey));
			sc.write( ByteBuffer.wrap(encryptedSymKey) );

			//print the starting list
			ByteBuffer listOfConnectedClientsBuf = ByteBuffer.allocate(1000);
			sc.read(listOfConnectedClientsBuf);
			String listOfConnectedClientsStr = readBufferIntoString(listOfConnectedClientsBuf);
			System.out.println("Here are the clients that are connected to the server: " + listOfConnectedClientsStr);
			
			
			//TODO get the public key in the correct formate 
			//PublicKey pubKey = ;
			//might need to get the key back into the PublicKey format because of tyoe errors?
			
			
			
			// byte encryptedsecret[] = client.RSAEncrypt(s.getEncoded()); //asymetric encryption of the key
			// SecureRandom r = new SecureRandom();
			// byte ivbytes[] = new byte[16];
			// r.nextBytes(ivbytes); //making a random IV
			// IvParameterSpec iv = new IvParameterSpec(ivbytes);
			// String plaintext = "This is a test string to encrypt"; //the message
			// byte ciphertext[] = client.encrypt(plaintext.getBytes(),s,iv); //symmetric method, (message,key,iv)
			// System.out.printf("CipherText: %s%n",DatatypeConverter.printHexBinary(ciphertext)); //coded message to be sent
			

			
			// IvParameterSpec iv = generateIV();
			//TODO need to encrypt the symetric key with the public key and TODO send it
			
			
			//start the threads
			sendThread.start(); //eachtime something is sent it goes through a process
			receiveThread.start(); 
			
      	}catch(IOException e){
      	    System.out.println("Got an exception: " + e);
      	}
          }

	class ChatClientRecieveThread extends Thread{
		SocketChannel sc;
		ChatClientRecieveThread(SocketChannel channel){
			sc = channel;
		}
	
		public void run(){
			
			while(true){
				try{
					// System.out.println("\t Who do you want to message (Enter client number or all):");
					// going back to what they were doing
					// Recieve Message
					ByteBuffer buffer = ByteBuffer.allocate(10000);
					ByteBuffer ivbuf = ByteBuffer.allocate(16);
					sc.read(ivbuf);
					sc.read(buffer);

					IvParameterSpec iv = new IvParameterSpec(ivbuf.array());
					System.out.println("Iv recieved from client: " + iv.toString() + "Of size " + iv.getIV().length );
					
					byte ciphertext[] = getCorrectSizeCiphertext(buffer);
					System.out.println("Length of message: " + ciphertext.length);
					// Decrypt
					byte decryptedplaintext[] = decrypt(ciphertext,symKey,iv); //decrypt the symetric key
					String msgFromClient = new String(decryptedplaintext); // the final message
					System.out.printf("Got message: %s%n",msgFromClient);

					String receivedMessage = msgFromClient;
					// System.out.println(receivedMessage);
					
					if( receivedMessage.equals(kickUserString) || receivedMessage.contains(kickUserString) || Objects.equals(receivedMessage, kickUserString)){
							System.out.println("\n YOU ARE BEING KICKED - GOODBYE");
							sc.close();
							System.exit(-1); // Have to exit with code -1 so that it kills the whole 
					}else{
							//System.out.println("\n ****Got message****: " + receivedMessage );
						}
				} catch(Exception e){
						System.out.println("Got error while trying to recieve message: "  + e);
					}
				
			}
			
		}		
	}

	/*
		Sending Messages
			-Make a new random IV
			-Symetric encrypt message with the IV
			-Send the message to the server
	
	*/
	class ChatClientSendThread extends Thread{
		SocketChannel sc;
		ChatClientSendThread(SocketChannel channel){
			sc = channel;
		}
		public void run(){
			try{
				
				Console cons = System.console();
				SecretKey thisSymKey = getSymKey();
				
				
				while(true){ // Send/recieve messages loop
							// Send Message
					String destination = cons.readLine("\n Who do you want to message (Enter client number or all): "); 
					//The other clients who can be messaged have names like 0, 1, 2, 3, etc. 
					String message  = cons.readLine("\n Message: ");
					String messageToServerPlainText = destination + "|" + message; // Will split the message on "|" on server side
					System.out.println("Length of message: " + messageToServerPlainText.length());
					// Generate IV
					SecureRandom r = new SecureRandom();
					byte ivbytes[] = new byte[16];
					r.nextBytes(ivbytes);
					IvParameterSpec iv = new IvParameterSpec(ivbytes);
					System.out.println("sym key from client: " + thisSymKey.toString());
					System.out.println("Iv from client: " + iv.toString());

					byte ciphertext[] = encrypt(messageToServerPlainText.getBytes(),thisSymKey,iv);
					System.out.printf("CipherText: %s%n",DatatypeConverter.printHexBinary(ciphertext)+ '\n'); //coded message to be sent
					// send the ciphertext and the IV in a bytebuffer - make a method to make the bytebuffer
					System.out.println("ZIS ES ZE ZIZE OF ZE IV: " + iv.getIV().length);
					ByteBuffer ivBuffer = ByteBuffer.wrap(iv.getIV());
					System.out.println("siiiiiiiiiize of the ciphertext!: " + ciphertext.length);
					ByteBuffer cipherBuffer = ByteBuffer.allocate(10000);
					//cipherBuffer = cipherBuffer.put(ciphertext);
					cipherBuffer = ByteBuffer.wrap(ciphertext);
					System.out.println("siiiiiiiiiize of the cipherbuffer!: " + cipherBuffer.array().length);

					sc.write(ivBuffer); // send the buffer with the destination and the message
					sc.write(cipherBuffer);
				}
			} catch(Exception e){
					System.out.println("Got error while trying to recieve message: "  + e);
					}
				
		}
	}

}
