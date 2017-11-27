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
import java.util.Objects;
import java.lang.Math.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import javax.xml.bind.DatatypeConverter;


class chatClient{
	public String kickUserString = "123456789GOODBYE987654321";
	//private PrivateKey privKey; only the server knows what this is 
    private PublicKey pubKey;
    
    public chatClient(){
    	//privKey=null;
		pubKey=null;
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
			
			//print the starting list
			ByteBuffer listOfConnectedClientsBuf = ByteBuffer.allocate(1000);
			sc.read(listOfConnectedClientsBuf);
			String listOfConnectedClientsStr = readBufferIntoString(listOfConnectedClientsBuf);
			System.out.println("Here are the clients that are connected to the server: " + listOfConnectedClientsStr);
			
			ByteBuffer publicKey = ByteBuffer.allocate(10000);
			
			sc.read(publicKey);
			//TODO get the public key in the correct formate 
			//PublicKey pubKey = ;
			//might need to get the key back into the PublicKey format because of tyoe errors?
			System.out.println("Client has the public key."); //TODO fix this sending on the server side
			
			SecretKey s = client.generateAESKey(); //making the Symetric key
			
			byte encryptedsecret[] = c.RSAEncrypt(s.getEncoded()); //asymetric encryption of the key
			SecureRandom r = new SecureRandom();
			byte ivbytes[] = new byte[16];
			r.nextBytes(ivbytes); //making a random IV
			IvParameterSpec iv = new IvParameterSpec(ivbytes);
			//TODO need to encrypt the symetric key with the public key and TODO send it
			
			
			//start the threads
			sendThread.start(); //eachtime something is sent it goes through a process
			receiveThread.start(); 
			
			
			// while(true){ // Send/recieve messages loop
			// 	// Send Message
			// 	String destination = cons.readLine("Who do you want to message (Enter client number or all) : "); 
			// The other clients who can be messaged have names like 0, 1, 2, 3, etc. 
			// 	String message  = cons.readLine("Message: ");
			// 	String messageToServer = destination + "|" + message; // Will split the message on "|" on server side
			// 	ByteBuffer sendBuf = ByteBuffer.wrap(messageToServer.getBytes());
			// 	sc.write(sendBuf); // send the buffer with the destination and the message
			// 	}
			
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
					System.out.println("\t Who do you want to message (Enter client number or all):");
					// going back to what they were doing
					// Recieve Message
					ByteBuffer messageFromServer = ByteBuffer.allocate(10000);
					sc.read(messageFromServer);
					String receivedMessage = readBufferIntoString(messageFromServer);
					
					if( receivedMessage.equals(kickUserString) || receivedMessage.contains(kickUserString) || Objects.equals(receivedMessage, kickUserString)){
							System.out.println("\n YOU ARE BEING KICKED - GOODBYE");
							sc.close();
							System.exit(-1); // Have to exit with code -1 so that it kills the whole 
					}else{
							System.out.println("\n ****Got message****: " + receivedMessage );
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
				
				
				
				while(true){ // Send/recieve messages loop
							// Send Message
					String destination = cons.readLine("\n Who do you want to message (Enter client number or all): "); 
					//The other clients who can be messaged have names like 0, 1, 2, 3, etc. 
					String message  = cons.readLine("\n Message: ");
					String messageToServer = destination + "|" + message; // Will split the message on "|" on server side
					ByteBuffer sendBuf = ByteBuffer.wrap(messageToServer.getBytes());
					sc.write(sendBuf); // send the buffer with the destination and the message
				}
			} catch(Exception e){
					System.out.println("Got error while trying to recieve message: "  + e);
					}
				
		}
	}

}
