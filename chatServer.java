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



class chatServer{
	public static ConcurrentHashMap<Integer, SocketChannel> clientMap = new ConcurrentHashMap<Integer, SocketChannel>();

	public static SocketChannel getFromClientMap(int clientNum){ //Gets the socketChannel from the map
		return clientMap.get(clientNum);
	} 
	
	public void putIntoClientMap(int clientNum, SocketChannel sc){ // put key-value pair into map
		clientMap.put(clientNum, sc);
	}
	
	public chatServer(){}

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
		SocketChannel channel = clientMap.get(user);
		String kickUserString = "123456789GOODBYE987654321";
		try{
			channel.write(ByteBuffer.wrap(kickUserString.getBytes()));
		} catch(Exception exception){
			System.out.println("Caught error while sending message to all: " + exception);
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

    public static void main(String args[]){
		chatServer server = new chatServer();
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
					System.out.println("Put client " + clientNum + " into map " + clientMap.toString());
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

			// Read message from client
			ByteBuffer buffer = ByteBuffer.allocate(10000);
			sourceSocketChannel.read(buffer);
			String msgFromClient = readBufferIntoString(buffer);
			System.out.println("Got message from client: " + msgFromClient);

			// Get the destination from the message
			int destinationInt = getDestination(msgFromClient);
			if(destinationInt != -1){ // -1 means that there was not a specific destination
				System.out.println("Successfully got the destination from the message - sending to: " + destinationInt);

				// Instantiate the connection to the destination - use clientMap to do this
				SocketChannel destinationSocketChannel = getFromClientMap(destinationInt);
				
				// Get the actual message to be sent to the destination
				ByteBuffer msgToSend = getMessage(msgFromClient);
				System.out.println("Sending message to client: "  + msgToSend);

				// Send the message to the destination
				destinationSocketChannel.write(msgToSend);
			}
		
	    }catch(IOException e){
			System.out.println("Got an Exception: " + e);
	    }

	}
    }
}
