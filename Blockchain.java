/*--------------------------------------------------------

1. Name / Date: 

	Wenwen Zhang  10/28/2017

2. Java version used, if not the official version for the class:

	build 1.8.0_121-b13

3. Precise command-line compilation examples / instructions:

	> javac Blockchain.java

4. Precise examples / instructions to run this program:

	In three separate shell windows, run the following commands.	
	
	> java Blockchain 0
	> java Blockchain 1
	> java Blockchain 2
	
	Process 0 should be started first, then Process 1, and Process 2 is
	the last process to be started.

5. List of files needed for running the program.

 	a. Blockchain.java
 	b. BlockInput0.txt
 	c. BlockInput1.txt
 	d. BlockInput2.txt

6. Notes:

	a. When all three processes have been started, they will automatically 
	communicate with each other, have the public keys sent, text files read, 
	unverified blocks sent, and the shared ledger ready and written to disk.
	
	b. Once the ledger is updated and agreed by each process, a list of 
	operations will show up on console for user to choose.
		Enter "R filename" to add new data, 
			  "L" to list the records,
		      "V" to verify the blockchain and report process credit,
			  "V threshold" to verify the work threshold,
			  "V hash" to verify the SHA256 string, 
	          "V signature" to verify the signature,
			  "V datahash" to verify the data, 
			  "quit" to exit 	

----------------------------------------------------------*/

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.StringWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Random;
import java.util.UUID;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.security.MessageDigest; 


public class Blockchain 
{ 
	public static void main(String[] args) throws Exception {

		int pid; //Specify the process ID.
		
		// Get the process ID from the argument.
		if (args.length == 1)
			pid = Integer.parseInt(args[0]);
		else
			pid = 0;

		Process p = new Process(pid); //Create a new process with the process ID.

		System.out.println("Process " + p.processId + " is listening at " 
							+ p.unverifiedPort + " and " + p.updatedPort + "\n");

		//Create a thread to receive the updated blockchain.
		BlockchainThread BCT = new BlockchainThread(p);
		Thread bct = new Thread(BCT);
		bct.start();
		
		//Create a thread to receive the unverified blocks and the public keys.
		UnverifiedThread UnT = new UnverifiedThread(p);
		Thread unt = new Thread(UnT);
		unt.start();

		//Create a thread to work on the updated ledgers received.
		BlockLedgerThread BLT = new BlockLedgerThread(p);
		Thread blt = new Thread(BLT);
		blt.start();
		
		//If the process ID is 2, and public key has not sent yet, send the public key to other peers.
		if (p.processId == 2 && !p.publicKeySent) {
			p.sendKeys(p);
		}
		
		//A buffered reader to contain the input from the console later.
		BufferedReader inputHolder = new BufferedReader(new InputStreamReader(System.in));

		String entry = ""; //User's input
		
		//Based on the process ID, get the corresponding filename.
		String Filename = ""; 
		switch (pid) {
		case 1:
			Filename = "BlockInput1.txt";
			break;
		case 2:
			Filename = "BlockInput2.txt";
			break;
		default:
			Filename = "BlockInput0.txt";
			break;
		}

		while (true) {

			Thread.sleep(100); //Wait to make sure the public keys have been established.
			
			//Read the data when the process has been initialized and the fileRead flag is still off.
			if (p.initialized() && (!p.fileRead)) {
				p.readFile(Filename);
			}
			
			//When the unverified queue is not empty, work on the unverified blocks 
			//and then solve the puzzle in order to add to the ledger.
			if (p.initialized() && (p.unverifiedQueue.peek() != null)) {
				p.solvePuzzle();
			}
			
			//When the process is initialized and the Ledger has been established, 
			//prompt the user to enter operation and display corresponding results.
			if (p.initialized() && p.unverifiedQueue.peek() == null && p.receivedLedger.peek() == null) {
				do {
					Thread.sleep(100);
					System.out.print("Enter your operation:\n" 
									+ "    \"R filename\" to add new data\n"
									+ "    \"L\" to list the records\n"
									+ "    \"V\" to verify the blockchain and report process credit\n"
									+ "    \"V threshold\" to verify the work threshold\n"
									+ "    \"V hash\" to verify the SHA256 string\n" 
									+ "    \"V signature\" to verify the signature\n"
									+ "    \"V datahash\" to verify the data\n"
									+ "    \"P\" to show the ledger\n" 
									+ "    or \"quit\" to exit: ");

					System.out.flush();

					entry = inputHolder.readLine(); //Read the input.

					//Verify the ledger and report the credit of each process.
					if (entry.toUpperCase().equals("V")) {
						p.simpleVerify();
					}

					//List the records.
					else if (entry.toUpperCase().equals("L")) {
						p.listRecords();
					}
					
					//Verified the threshold, the threshold here is "AAA". 
					//The hash string that ends with "AAA" meet the criteria.
					else if (entry.toUpperCase().equals("V THRESHOLD")) {
						p.verifyThreshold();
					}

					//Verify the hash string.
					else if (entry.toUpperCase().equals("V HASH")) {
						p.verifyHash();
					} 
					
					//Verify the signature of the verifying process.
					else if (entry.toUpperCase().equals("V SIGNATURE")) {
						p.verifySignature();
					} 
					
					//Verify the dataHash with the local stored records of the creating process
					else if (entry.toUpperCase().equals("V DATAHASH")) {
						p.verifyData();
					}
					
					//Print the ledger to console.
					else if (entry.toUpperCase().equals("P")) {
						System.out.println();
						System.out.println(p.getLedger());
						System.out.println();
					}
					
					//Read new data, add to the ledger.
					else if (entry.startsWith("R") || entry.startsWith("r")) {
						
						//get the filename only when the input length is greater that 2.
						if (entry.length() > 2) { 
							
							//Get the input file name, then read data and update ledger.
							String filename = entry.substring(entry.indexOf(" ") + 1);
							//Read the file.
							p.readFile(filename);
							//Tell the peers to work on the blocks.
							p.clientWork(p, false, "work");
							//Start to unverify the blocks.
							p.solvePuzzle();						
						}
					}
				}

				// When 'quit' is typed, close this client.
				while (!entry.equals("quit"));
				System.out.println("Cancelled by user request.");
				System.exit(0);
			}
		}
	}
}


class Process
{
	//The process id of this instance, and the process id of other peers.
	public int processId;
	public int peer1Id;
	public int peer2Id;
	
	//Two port numbers that is based on the processId.
	public int unverifiedPort;
    public int updatedPort;
	
	//Public keys of other peers.
	public PublicKey peer1Key = null;
	public PublicKey peer2Key = null;
	
	//The key pair of the process object.
	public KeyPair keys;
	public long keySeed = new Random().nextLong();
	
	//Some flags to control the program flow
    public boolean publicKeySent = false;
    public boolean peer1KeyReceived = false;
    public boolean peer2KeyReceived = false;
    public boolean fileRead = false;
    
    //The Ledger that will be updated and sent out.
    public String blockLedger = "";
    
    //A dummy block as the first entry of the ledger
    public String dummy = convertToString(dummyBlock());

    //An array to contain the records read from the file.
    public BlockRecord [] blockChain = new BlockRecord [20];
    
    //Two queues to contain data 
    public Queue <String> receivedLedger; //for the received ledgers.  
    public Queue <String> unverifiedQueue; //for unverified blocks.
    
    //An arraylist to contain the dataHash of the records created by the instance.
    ArrayList<String> localData; 
   
    //XML header.
    public static String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
    
    //Constructor
	Process(int pid) {
		
		processId = pid; //Set the process ID

		//Set the IDs of the peers.
		if (processId == 0) {
			peer1Id = 1;
			peer2Id = 2;
		} else if (processId == 1) {
			peer1Id = 0;
			peer2Id = 2;
		} else if (processId == 2) {
			peer1Id = 0;
			peer2Id = 1;
		}

		//Generate the key pair.
		keys = generateKeyPair(keySeed);

		//Set the port numbers.
		unverifiedPort = 4710 + processId;
		updatedPort = 4820 + processId;

		//Complete the header of the dummy block.
		String first = addSeed(dummy, "N/A");
		first = addVerifyPID(first, "N/A");
		first = addVerifyTimestamp(first, "N/A");
		first = addPreviousHash(first, "N/A");
		first = addSHA(first, "N/A", "N/A");
		first = addBlockNum(first, "0");

		//Format the ledger.
		blockLedger = first.substring(0, first.indexOf("<blockRecord>")) + "<BlockLedger>\n"
				+ first.substring(first.indexOf("<blockRecord>")) + "</BlockLedger>\n";

		//Construct the data structures.
		unverifiedQueue = new LinkedList<String>();
		receivedLedger = new LinkedList<String>();
		localData = new ArrayList<String>();
	}
	
	//Create a dummy block which will be the same for all process 
		//and is the first entry of the ledger.
		public static BlockRecord dummyBlock() {
			
			BlockRecord dummy = new BlockRecord();

			dummy.setCBlockID("N/A");
			dummy.setCSignedBlockID("N/A");
			dummy.setDCreatingProcess("N/A");
			dummy.setDTimeStamp("N/A");
			dummy.setEDataHash("N/A");
			dummy.setFSSNum("N/A");
			dummy.setFFname("N/A");
			dummy.setFLname("N/A");
			dummy.setFDOB("N/A");
			dummy.setGDiag("N/A");
			dummy.setGTreat("N/A");
			dummy.setGRx("N/A");
			
			return dummy;
		}

	//Generate the key pair.
	public KeyPair generateKeyPair(long seed) {
		KeyPairGenerator keyGenerator = null;
		try {
			keyGenerator = KeyPairGenerator.getInstance("RSA");
			SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
			rng.setSeed(seed);
			keyGenerator.initialize(1024, rng);

		} catch (Exception e) {e.printStackTrace();}

		return (keyGenerator.generateKeyPair());
	}
	
	//An utility function to sign the data with the private key
	public byte[] signData(byte[] data, PrivateKey key) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initSign(key);
		signer.update(data);
		return (signer.sign());
	}
	//An utility function to verify the data with the public key.
	public boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initVerify(key);
		signer.update(data);
		return (signer.verify(sig));
	}

	//Convert the received string-formatted public key to PublicKey object.
	public PublicKey savePublicKey(String msg) throws Exception {
		PublicKey publicKey;
		byte[] keyBytes = Base64.getMimeDecoder().decode(msg);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		publicKey = kf.generatePublic(new X509EncodedKeySpec(keyBytes));
		return publicKey;
	}
	
	//Send out the public key of this process
	public synchronized void sendKeys(Process p) {
		
		//Convert the public key to String
		PublicKey key = p.keys.getPublic();
		byte[] keyBytes = key.getEncoded();
		String keyString = Base64.getMimeEncoder().encodeToString(keyBytes);

		//Send keys to the peers.
		clientWork(p, false, keyString);

		p.publicKeySent = true; //Turn on the flag.
	}
	
	//Convert the XML to BlockRecord object.
	public BlockRecord convertToBlock(String msg) {

		JAXBContext jaxbContext;
		BlockRecord br = null;
		try {
			jaxbContext = JAXBContext.newInstance(BlockRecord.class);
			Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
			StringReader reader = new StringReader(msg);
			br = (BlockRecord) jaxbUnmarshaller.unmarshal(reader);
			
		} catch (Exception e) {e.printStackTrace();}
		return br;
	}
	
	//An utility method to convert the BlockRecord object to XML string.
	public String convertToString(BlockRecord br) {
		JAXBContext jaxbContext;
		String xml = "";
		try {
			jaxbContext = JAXBContext.newInstance(BlockRecord.class);
			Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
			StringWriter sw = new StringWriter();
			jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
			jaxbMarshaller.marshal(br, sw);
			xml = sw.toString();
		} catch (JAXBException e) {e.printStackTrace();}
		return xml;
	}

	//Add block sequence number to the verified blocks.
	public String addBlockNum(String br, String n) {
		return br.substring(0, br.indexOf("<SignedSHA256>")) + "<BlockNum>" + n + "</BlockNum>\n    "
				+ br.substring(br.indexOf("<SignedSHA256>"));
	}
	
	//Add seed to blocks.
	public String addSeed(String br, String seed) {
		return br.substring(0, br.indexOf("<CBlockID>")) + "<Seed>" + seed + "</Seed>\n    "
				+ br.substring(br.indexOf("<CBlockID>"));
	}
	
	//Change seed when the seed inserted does not solve the puzzle.
	public String changeSeed(String br, String seed) {
		String temp = br.substring(0, br.indexOf("<Seed>") + "<Seed>".length()) + ""
				+ br.substring(br.indexOf("</Seed>"));
		return temp.substring(0, br.indexOf("<Seed>") + "<Seed>".length()) + seed
				+ temp.substring(temp.indexOf("</Seed>"));
	}

	//Add verifying process ID to the verified blocks.
	public String addVerifyPID(String br, String pid) {
		return br.substring(0, br.indexOf("<Seed>")) + "<VerificationProcessID>" + "Process " + pid
				+ "</VerificationProcessID>\n    " + br.substring(br.indexOf("<Seed>"));
	}
	
	//Add verified time.
	public synchronized String addVerifyTimestamp(String br, String time) {
		return br.substring(0, br.indexOf("<VerificationProcessID>")) + "<VerifiedTime>" + time
				+ "</VerifiedTime>\n    " + br.substring(br.indexOf("<VerificationProcessID>"));
	}
	
	//Add previous hash string to the verified blocks.
	public String addPreviousHash(String br, String hash) {
		return br.substring(0, br.indexOf("<VerifiedTime>")) + "<PreviousHash>" + hash + "</PreviousHash>\n    "
				+ br.substring(br.indexOf("<VerifiedTime>"));
	}

	//Add SHA256 string.
	public String addSHA(String br, String sig, String sha) {
		return br.substring(0, br.indexOf("<PreviousHash>")) + "<SignedSHA256>" + sig + "</SignedSHA256>\n    "
				+ "<SHA256String>" + sha + "</SHA256String>\n    " + br.substring(br.indexOf("<PreviousHash>"));
	}

	//Get the Block ID.
	public String getUnverifiedBlockID(String br) {
		return br.substring(br.indexOf("<CBlockID>") + "<CBlockID>".length(), br.indexOf("</CBlockID>"));
	}
	
	//Get the creating process ID.
	public String getCreatingP(String br) {
		return br.substring(br.indexOf("<DCreatingProcess>") + "<DCreatingProcess>Process ".length(),
				br.indexOf("</DCreatingProcess>"));
	}

	//Get the signed block ID.
	public String getSignedBlockId(String br) {
		return br.substring(br.indexOf("<CSignedBlockID>") + "<CSignedBlockID>".length(),
				br.indexOf("</CSignedBlockID>"));
	}
	
	//Get the block sequence number.
	public String getBlockNum(String br) {
		return br.substring(br.indexOf("<BlockNum>") + "<BlockNum>".length(), br.indexOf("</BlockNum>"));
	}

	//Get the SHA256 string.
	public String getSHA256Hash(String br) {
		return br.substring(br.indexOf("<SHA256String>") + "<SHA256String>".length(), br.indexOf("</SHA256String>"));
	}

	//Get the Signed SHA256 string.
	public String getSignedSHA256Hash(String br) {
		return br.substring(br.indexOf("<SignedSHA256>") + "<SignedSHA256>".length(), br.indexOf("</SignedSHA256>"));
	}
	
	//Get the verifying process id
	public String getVerifyProcess(String br) {
		return br.substring(br.indexOf("<VerificationProcessID>") + "<VerificationProcessID>Process ".length(),
				br.indexOf("</VerificationProcessID>"));
	}

	//Add unverified blocks to queue.
	public synchronized void addUnverified(String msg) {
		this.unverifiedQueue.add(msg);
	}

	//Get an unverified block, and then remove it from the queue.
	public synchronized String getUnverified() {
		return this.unverifiedQueue.poll();
	}

	//Add updated ledgers received to queue.
	public synchronized void addVerified(String msg) {
		this.receivedLedger.add(msg);
	}
	
	//Get an updated ledger, and then remove it from the queue.
	public synchronized String getVerified() {
		return this.receivedLedger.poll();
	}


	//Check if the process has been initialized, i.e. keys established, 
	public boolean initialized() {
		return publicKeySent && peer1KeyReceived && peer2KeyReceived;
	}
	
	//Check if the block ID is in the ledger.
	public boolean isExist(String bID) {
		return getLedger().contains(bID);
	}

	//Verified the signed block ID using the public key of the creating process.
	public boolean blockIdVerified(String br) {
		
		String signedBID = getSignedBlockId(br); //Get signed block id.
		String BID = getUnverifiedBlockID(br); //Get block id.
		int pid = Integer.parseInt(getCreatingP(br)); //Get the creating process id.	
		
		boolean result = false;

		//If the creating process is not this process, verify.
		if (pid != this.processId) {
			
			//Grab the correct public key
			PublicKey key = ((pid == this.peer1Id) ? this.peer1Key : this.peer2Key); 
			try {
				//Verify the signed block id using the public key.
				result = verifySig(BID.getBytes(), key, Base64.getDecoder().decode(signedBID));
			} catch (Exception e) {e.printStackTrace();}
		} else
			result = true;

		return result;
	}
	
	//Check if the parameter has a lower time stamp when compared to the current ledger.
	public boolean lowerTimestamp(String br) {
		
		String curr = getLedger(); //Get the current ledger.

		//Get the verification time of the first block of the parameter.
		String ts1 = br.substring(br.indexOf("<VerifiedTime>") + "<VerifiedTime>".length(),
				br.indexOf("</VerifiedTime>"));
		
		//Get the verification time of the first block of the current ledger.
		String ts2 = curr.substring(curr.indexOf("<VerifiedTime>") + "<VerifiedTime>".length(),
				curr.indexOf("</VerifiedTime>"));
		//Check year
		if (Integer.parseInt(ts1.substring(0, 4)) < Integer.parseInt(ts2.substring(0, 4)))
			return true;
		//Check month
		else if (Integer.parseInt(ts1.substring(5, 7)) < Integer.parseInt(ts2.substring(5, 7)))
			return true;
		//Check day
		else if (Integer.parseInt(ts1.substring(8, 10)) < Integer.parseInt(ts2.substring(8, 10)))
			return true;
		//check hour
		else if (Integer.parseInt(ts1.substring(11, 13)) < Integer.parseInt(ts2.substring(11, 13)))
			return true;
		//check minute
		else if (Integer.parseInt(ts1.substring(14, 16)) < Integer.parseInt(ts2.substring(14, 16)))
			return true;
		//check second
		else if (Integer.parseInt(ts1.substring(17, 19)) < Integer.parseInt(ts2.substring(17, 19)))
			return true;
		//check millisecond
		else if (Integer.parseInt(ts1.substring(20, 23)) < Integer.parseInt(ts2.substring(20, 23)))
			return true;
		else
			return false;
	}
	
	//Get the length of the passed ledger
	public int count(String br) {
		int count = 0;
		final String toFind = "<blockRecord>";
		int lastIndex = 0;
		while (lastIndex != -1) {
			lastIndex = br.indexOf(toFind, lastIndex);
			if (lastIndex != -1) {
				count++;
				lastIndex += toFind.length();
			}
		}
		return count;
	}

	//Add the verified block to Ledger.
	public void addToLedge(String br) {
		
		String temp = getLedger();
		String temp2 = br.replace(Process.XMLHeader, "");
		setLedger(temp.substring(0, temp.indexOf("\n<blockRecord>")) + temp2 + "\n"
				+ temp.substring(temp.indexOf("<blockRecord>")));
	}

	//Send the updated ledger to other peers via 4820+ ports.
	public void sendLedger(String msg) {
		clientWork(this, true, msg);
	}
	
	//A synchronized method to get the ledger
	public synchronized String getLedger() {
		return this.blockLedger;
	}
	
	//A synchronized method to set the ledger
	public synchronized void setLedger(String block) {
		this.blockLedger = block;
	}
	
	//Return a cleaned block without header
	public String cleanLedger(String bc) {
		String res = bc.replace(XMLHeader + "\n<BlockLedger>\n", "");
		res = res.replace("\n</BlockLedger>\n", "");
		return res;
	}

	//Work on the unverified blocks and solve puzzle in order to add to the ledger.
	public void solvePuzzle() {

		System.out.println("Creating blockchain ledger...\n");
		String bid = "";	
		String blockVerified;

		try {

			while (unverifiedQueue.peek() != null) {
				
				blockVerified = getUnverified(); //Grab one block from the queue.
				
				bid = getUnverifiedBlockID(blockVerified); //Get the block Id.

				//Continue to solve the puzzle only if the block id is not in the ledger 
				//and the block id is verified.
				if (!isExist(bid) && blockIdVerified(blockVerified)) {
					
					blockVerified = addSeed(blockVerified, "N/A");

					String seed = "";

					Random r = new Random();

					//Check if the block is in the ledger
					while (!isExist(bid)) {

						seed = Integer.toString(r.nextInt()); //Choose a random number

						blockVerified = changeSeed(blockVerified, seed); //Insert the random number
						
						//Get the hash string of the first block of current ledger.
						String currentFirstHash = getSHA256Hash(getLedger()); 
						
						//Get the block sequence number of current ledger
						String currentNum = getBlockNum(getLedger()); 
						
						//Set the sequence number of this unverified block
						int newNum = Integer.parseInt(currentNum) + 1; 

						//Concatenate the current hash with the block data
						String DataToHash = currentFirstHash + blockVerified.substring(blockVerified.indexOf("<Seed>"),
								blockVerified.indexOf("</blockRecord>"));
						
						//Create a hash of the concatenated string to solve the puzzle
						String guessStr = dataHash(DataToHash);

						//If the random string ends with "AAA", then the puzzle is solved
						//Then continue after checking if the block is added to the ledger already
						if (guessStr.toUpperCase().endsWith("AAA") && !isExist(bid)) {
							
							//Add the verifying process id
							blockVerified = addVerifyPID(blockVerified, Integer.toString(this.processId));
							
							//Add verifying time stamp.
							String time = LocalDateTime.now()
									.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
							blockVerified = addVerifyTimestamp(blockVerified, time);
							
							//Insert the current first hash to the previous hash field
							blockVerified = addPreviousHash(blockVerified, currentFirstHash);
							
							//Get the hash string of this verified block, then add to the block
							String dataTohash = blockVerified.substring(blockVerified.indexOf("<PreviousHash>"),
									blockVerified.indexOf("</blockRecord>"));
							String SHA256 = dataHash(dataTohash);

							//Signed the SHA256 string and insert to block.
							byte[] sigSHA256 = signData(SHA256.getBytes(), this.keys.getPrivate());
							String sigSHA256String = Base64.getEncoder().encodeToString(sigSHA256);
							blockVerified = addSHA(blockVerified, sigSHA256String, SHA256);
							
							//Add block sequence number.
							blockVerified = addBlockNum(blockVerified, Integer.toString(newNum));

							//Check if this block is added again, if not, update the ledger, and send to peers.
							if (!isExist(bid)) {
								addToLedge(blockVerified);
								sendLedger(getLedger());
							}
							break; //Stop working on this block, continue to the next unverified block.
						}
					}
				}
				
				//Call this function to write the ledger to file if the process id is 0.
				//And print messages show the file has been written.			
				writeLedger(); 

			}
		} catch (Exception e) {e.printStackTrace();}
	}
	
	//Read the data from file, create unverified blocks and send out to peers.
	public void readFile(String Filename) {

		try {
			Thread.sleep(100);
		} catch (InterruptedException e1) {e1.printStackTrace();}
		System.out.println("\nReading data from " + Filename + " ...\n");
		
		final int pid = this.processId; //Get the creating process id

		//Index of content tokens in file
		final int iFName = 0;
		final int iLName = 1;
		final int iDOB = 2;
		final int iSSN = 3;
		final int iDiag = 4;
		final int iTreat = 5;
		final int iRX = 6;

		try {
			try (BufferedReader br = new BufferedReader(new FileReader(Filename))) {
				
				String[] tokens = new String[10];
				String InputLineStr;
				String suuid;
				BlockRecord[] blockArray = new BlockRecord[20]; // To store the block records
				int n = 0;

				while ((InputLineStr = br.readLine()) != null) {
					
					//Create a new BlockRecord using the contents in the file. 
					//One line for one block.
					blockArray[n] = new BlockRecord();
					tokens = InputLineStr.split(" +");
					
					blockArray[n].setFSSNum(tokens[iSSN]);
					blockArray[n].setFFname(tokens[iFName]);
					blockArray[n].setFLname(tokens[iLName]);
					blockArray[n].setFDOB(tokens[iDOB]);
					blockArray[n].setGDiag(tokens[iDiag]);
					blockArray[n].setGTreat(tokens[iTreat]);
					blockArray[n].setGRx(tokens[iRX]);

					//Hash the data and save it as dataHash both in the block and in localData
					String dataRaw = convertToString(blockArray[n]);
					String dataToHash = dataRaw.substring(dataRaw.indexOf("<blockRecord>") + "<blockRecord>".length(),
							dataRaw.indexOf("</blockRecord>"));
					String hashedData = dataHash(dataToHash);
					blockArray[n].setEDataHash(hashedData);
					localData.add(hashedData);

					//Create an unique block id and insert into block.
					suuid = new String(UUID.randomUUID().toString());
					blockArray[n].setCBlockID(suuid);
					
					//Add the creating process id.
					blockArray[n].setDCreatingProcess("Process " + pid); 

					//Sign the block id and insert into block.
					byte[] signature = signData(suuid.getBytes(), this.keys.getPrivate());
					String signedBlockID = Base64.getEncoder().encodeToString(signature);
					blockArray[n].setCSignedBlockID(signedBlockID);

					//Add creating time stamp.
					String time = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
					blockArray[n].setDTimeStamp(time + "." + pid);

					//Convert this BlockRecord to string
					String cleanBlock = convertToString(blockArray[n]);

					//Add this unverified block to local queue and send out to the peers.
					addUnverified(cleanBlock);
					clientWork(this, false, cleanBlock);

					//Count the blocks being created.
					n++;
				}
				this.fileRead = true; //Turn on the flag.
				Thread.sleep(100);
				System.out.println("\n" + n + " records read.\n");

			} catch (IOException e) {e.printStackTrace();}
		} catch (Exception e) {e.printStackTrace();}
	}

	//An utility method to hash the passes string parameter to SHA256 string.
	public String dataHash(String stringXML) {	
		String hash = "";
		try {		
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(stringXML.getBytes());
			byte byteData[] = md.digest();
			
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < byteData.length; i++) {
				sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
			}
			hash = sb.toString();
		} catch (Exception e) {e.printStackTrace();}		
		return hash;
	}
	
	//Make connection requests to the specified servers and send messages.
	public void clientWork(Process newP, boolean e, String newMsg) {
		
		String msg = newMsg;

		//If the boolean parameter is false, use unverified ports 4710+
		//If it is true, use blockchain ports 4820+
		int port = e ? 4820 : 4710;
		
		//Create another thread to handle the connection to the first peer.
		ClientThread CT = new ClientThread(newP, port + newP.peer1Id, msg);
		Thread ct = new Thread(CT);
		ct.start();

		//Send connection request to the second peer.
		Socket sock;
		try {
			sock = new Socket("localhost", port + newP.peer2Id);
			new ClientWorker(sock, newP, msg).start();
		} catch (Exception e1) {e1.printStackTrace();}
	}

	////A synchronized method to update the ledger with the received ledgers.
	public synchronized void updateLedger() {
		
		//Keep working when the queue is not empty
		while (receivedLedger.peek() != null) {		
			
			String temp = getVerified(); //Grab a ledger out from the queue.

			//Get the lengths of the current ledger and the recevied one.
			int lenN = count(temp);
			int lenC = count(getLedger());
			
			//Get the sequence numbers of the two ledgers.
			int tempSeq = Integer.parseInt(getBlockNum(temp));
			int currSeq = Integer.parseInt(getBlockNum(getLedger()));

			//If the received ledger contains or equals the current one,
			//replace current ledger with the new one.
			if (temp.contains(cleanLedger(getLedger()))) {
				setLedger(temp);
			}

			//If the received one is longer, the longer one wins. Then check if the blocks in the 
			//shorter one are all in the longer ledger, if not, send out the block as unverified block.
			else if (lenN > lenC && tempSeq > currSeq) {
				sendBackBlocks(temp, getLedger());
				setLedger(temp);
			}
			
			//If the lengths are the same, the one with lower time stamp wins. Then check if the blocks in the 
			//loser one are all in the updated ledger, if not, send out the block as unverified block.
			else if (lenN == lenC && tempSeq == currSeq) {
				if (lowerTimestamp(temp)) {
					sendBackBlocks(temp, getLedger());
					setLedger(temp);		
				}
			} 
			
			//Else, keep the current ledger, check if the blocks in the received ledger is in the current
			//blockchain, if not, send out the block as unverified block.
			else
			{
				sendBackBlocks(getLedger(), temp);				
			}
		}
	}
	
	//Check if the blocks in the second parameter is in the first parameter, 
	//if not, send the blocks back as unverified blocks.
	public void sendBackBlocks(String toKeep, String toSend) {

		//Get the length of the ledger to be checked
		int n = count(toSend);
		
		//Move the pointer to the start of the first block
		int index = toSend.indexOf("<blockRecord>"); 
		String temp = toSend.substring(index);
		
		String blockId;

		//Check all the blocks except for the last one which is a dummy entry.
		for (int i = 0; i < n - 1; i++) {
			
			blockId = getUnverifiedBlockID(temp); //Get the block id.			
			
			//If the block id is not in the to-keep ledger, send back.
			if (!toKeep.contains(blockId)) {

				String bye = Process.XMLHeader + "\n<blockRecord>\n    " + temp.substring(temp.indexOf("<CBlockID>"),
						temp.indexOf("</blockRecord>") + "</blockRecord>\n".length());

				//Add this block to local unverified queue and send to other peers.
				addUnverified(bye);
				clientWork(this, false, bye);
			} 

			//Update the pointer to point to the start of the next block.
			index = temp.substring(temp.indexOf("</blockRecord") + "</blockRecord>".length())
						.indexOf("<blockRecord>");
			temp = temp.substring(temp.indexOf("</blockRecord") + "</blockRecord>".length());
			temp = temp.substring(index);		
		}
	}

	//List the records in the ledger
	public void listRecords() {
		
		String record = getLedger(); //Get the current ledger.
		int cnt = count(record); //Get the length of the current ledger.
		
		//Get the index of the start of the first block
		int index = record.indexOf("<blockRecord>"); 
		
		String num = ""; //Get the block sequence number
		
		//The variables that would be used to get the content of the block.
		String bc = "";
		BlockRecord br;
		
		System.out.println();
		
		//List all the records except the last one which is a dummy entry
		for (int i = 0; i < cnt - 1; i++) {
			
			//Move the pointer to the start of the block
			record = record.substring(index);
			
			//Get block sequence number
			num = getBlockNum(record);
			
			//Re-format the block with header in order to convert to a BlockRecord object
			bc = Process.XMLHeader + "\n<blockRecord>\n    " + record.substring(record.indexOf("<CBlockID>"),
					record.indexOf("</blockRecord>") + "</blockRecord>\n".length());
			br = convertToBlock(bc);
			
			//Move the pointer to the next block
			index = record.substring(record.indexOf("</blockRecord>")).indexOf("<blockRecord>");
			record = record.substring(record.indexOf("</blockRecord>"));
			
			//List the information of the record.
			System.out.println(num + ". " + br.getDTimeStamp() + " " + br.getFFname() + " " + br.getFLname() + " "
					+ br.getFDOB() + " " + br.getFSSNum() + " " + br.getGDiag() + " " + br.getGRx());
		}		
		System.out.println();
	}

	//Simple verify the blocks in the ledger and report the verifying credit of each process
	//In this case, if the verification process field is not empty, the block is verified.
	public void simpleVerify() {
		
		String record = getLedger();
		int cnt = count(record);
		int index = record.indexOf("<blockRecord>");
		
		int id = 0;
		//Create an array to count the numbers of blocks verified by each process
		int[] arr = new int[3];

		int i = cnt;
		
		for (; i > 1; i--) {
			
			//Move the pointer to the start of the block
			record = record.substring(index);

			id = Integer.parseInt(getVerifyProcess(record));
			arr[id]++; //Increment the count of the specified process

			//Move the pointer to the next block.
			index = record.substring(record.indexOf("</blockRecord>")).indexOf("<blockRecord>");
			record = record.substring(record.indexOf("</blockRecord>"));
		}
		
		//Display the result.
		System.out.println("\nBlock " + i + "-" + (cnt - 1) + " in the blockchain have been verified.\nCredit: P0 = "
				+ arr[0] + ", P1 = " + arr[1] + ", P2 = " + arr[2] + ".\n");
	}

	//Verify each block by checking if it could meet the threshold
	//In this case, the threshold is the hash string ends with "AAA".
	public void verifyThreshold() {
		
		//Get the index ready
		String record = getLedger();	
		int index = record.indexOf("<blockRecord>");

		//Get the length
		int cnt = count(record);
	
		int i = cnt;

		String temp = "";
		String preHash = ""; 
		String newHash = "";

		while (i > 1) {
			
			//Move the pointer to the start of the block
			record = record.substring(index);

			//Get the SHA256 string of the previous block
			preHash = getSHA256Hash(record.substring(record.indexOf("</blockRecord>")));

			//Concatenate the previous hash with the block data starts from <Seed>.
			temp = preHash + record.substring(record.indexOf("<Seed>"), record.indexOf("</blockRecord>"));;

			//Get the new SHA256 hash string
			newHash = dataHash(temp);

			//If the new SHA256 string ends with "AAA", continue to verify the next one.
			if (newHash.toUpperCase().endsWith("AAA")) {
				
				index = record.substring(record.indexOf("</blockRecord>")).indexOf("<blockRecord>");
				record = record.substring(record.indexOf("</blockRecord>"));
				i--;
			} 
			//Else, if the threshold does not be met, break the for loop, print the summary message
			else {break;}
		}

		//If i is 1, it means all the blocks except the dummy entry has been verified.
		if (i == 1) {
			System.out.println("\nBlock " + i + "-" + (cnt - 1) + " in the blockchain have been verified.\n");
		}
		//Else, a block that does not meet the threshold has been detected.
		else {
			System.out.println("\nBlock " + i + " invalid: does not meet the work threshold.\nBlock " 
								+ (i + 1) + "-" + (cnt - 1) + " follow an invalid block.\n");
		}
	}

	//Verify each block by checking the SHA256 strings.
	public void verifyHash() {
		
		String record = getLedger();

		int cnt = count(record);
		int index = record.indexOf("<blockRecord>");

		int i = cnt;

		String temp = "";
		String trans = "";
		String preHash = "";
		String newHash = "";
		String currHash = "";

		while (i > 1) {
			record = record.substring(index);

			currHash = getSHA256Hash(record); //Get the current SHA256 hash.
			
			//Concatenate the SHA256 string with the block data to get a new SHA256 hash
			trans = record.substring(record.indexOf("</blockRecord>"));
			preHash = "<PreviousHash>" + getSHA256Hash(trans) + "</PreviousHash>\n    ";
			temp = preHash + record.substring(record.indexOf("<VerifiedTime>"), record.indexOf("</blockRecord>"));
			newHash = dataHash(temp);

			//If the new hash is the same as the current SHA256 in the block, this block then is verified.
			//Continue to the next one.
			if (newHash.equals(currHash)) {

				index = record.substring(record.indexOf("</blockRecord>")).indexOf("<blockRecord>");
				record = record.substring(record.indexOf("</blockRecord>"));
				i--;
			}
			//Else, break the for loop, print the summary message.
			else {break;}
		}

		//If i is 1, it means all the blocks except the dummy entry has been verified.
		if (i == 1) {
			System.out.println("\nBlock " + i + "-" + (cnt - 1) + " in the blockchain have been verified.\n");
		} 
		//Else, a block that has an unmatched SHA256 has been detected.
		else {
			System.out.println("\nBlock " + i + " invalid: SHA256 hash does not match.\nBlock " 
								+ (i + 1) + "-" + (cnt - 1) + " follow an invalid block.\n");
		}
	}

	//Verify each block by check the signatures.
	public void verifySignature() {

		String record = getLedger();
		int cnt = count(record);
		int index = record.indexOf("<blockRecord>");
		int id = 0;
		int i = cnt;

		String hash = "";
		String sigHash = "";

		PublicKey key;

		while (i > 1) {
			
			// Move the pointer to the start of the block.
			record = record.substring(index);
			
			//Get the SHA256 string
			hash = getSHA256Hash(record);

			//Get the signed SHA256 string.
			sigHash = getSignedSHA256Hash(record);

			//Get the verifying process id.
			id = Integer.parseInt(getVerifyProcess(record));

			//If the verifying process is the process itself, use its own public key.
			if (id == this.processId) {
				key = this.keys.getPublic();
			} 
			//Else, grab the correct public key.
			else {
				key = ((id == this.peer1Id) ? this.peer1Key : this.peer2Key);
			}
			try {
				//If the signed SHA256 string could be verified by the public key, continue to the next block
				if (verifySig(hash.getBytes(), key, Base64.getDecoder().decode(sigHash))) {
					index = record.substring(record.indexOf("</blockRecord>")).indexOf("<blockRecord>");
					record = record.substring(record.indexOf("</blockRecord>"));
					i--;
				}
				//Else, break the for loop, and print out summary message.
				else {
					break;
				}
			} catch (Exception e) {e.printStackTrace();}

		}
		//If i is 1, it means all the blocks except the dummy entry has been verified.
		if (i == 1) {
			System.out.println("\nBlock " + i + "-" + (cnt - 1) + " in the blockchain have been verified.\n");
		} 
		//Else, a block that has an unmatched signature has been detected.
		else {
			System.out.println("\nBlock " + i + " invalid: signature does not match the verifying process.\nBlock "
								+ (i + 1) + "-" + (cnt - 1) + " follow an invalid block.\n");
		}
	}

	//Verify the data with the local data records.
	public void verifyData() {
		
		String record = getLedger();
		int cnt = count(record);
		int index = record.indexOf("<blockRecord>");
		int id = 0;
		int i = cnt;

		String bc = "";
		BlockRecord br;
		String currDataHash = "";

		while (i > 1) {
			
			record = record.substring(index);

			//Get the creating process id.
			id = Integer.parseInt(getCreatingP(record));
			
			//If the creating process is this Process instance, check the dataHash.
			if (id == this.processId)
			{
				//Convert the block data to BlockRecord object.
				bc = Process.XMLHeader + "\n<blockRecord>\n    " + record.substring(record.indexOf("<CBlockID>"),
						record.indexOf("</blockRecord>") + "</blockRecord>\n".length());
				br = convertToBlock(bc);

				//Get the dataHash of the current block
				currDataHash = br.getEDataHash();

				//If the dataHash in the block does not match the local records, break the loop.
				if (!(localData.contains(currDataHash))) {
					break;
				}
			}
			
			//Continue to check the next one.
			index = record.substring(record.indexOf("</blockRecord>")).indexOf("<blockRecord>");
			record = record.substring(record.indexOf("</blockRecord>"));
			i--;
		}
		
		//If i is 1, it means all the blocks except the dummy entry has been verified.
		if (i == 1) {
			System.out.println("\nBlock " + i + "-" + (cnt - 1) + " in the blockchain have been verified.\n");
		}
		//Else, a block that has an unmatched dataHash has been detected.
		else {
			System.out.println("\nBlock " + i + " invalid: DataHash field does not match local records.\n");
		}
	}
	
	// Write the updated ledger to the disk and print notification messages.
	public void writeLedger() {
		
		// Write to disk only when both the queues are empty, which means the
		// ledger has been established.
		if (receivedLedger.peek() == null && initialized() && unverifiedQueue.peek() == null) {
			
			try {
				
				//System.out.println("Ledger updated.\n");

				//If the process id is 0, write to disk.
				if (processId == 0) {
					//System.out.println(getLedger());
					Thread.sleep(100);
					System.out.println("\nBlockchain ledger has been written to disk.\n");
				
					PrintWriter writer;
				
					writer = new PrintWriter("BlockchainLedger.xml", "UTF-8");
					writer.print(getLedger());
					writer.close();
				} 
				//If the process id is not 0, print messages to console.
				else {
					Thread.sleep(100);
					System.out.println("\nBlockchain ledger has been written to disk by Process 0.\n");
				}
			} catch (Exception e) {e.printStackTrace();}
		}
	}
}

//A thread to handle the communications of unverified blocks and public keys.
class UnverifiedThread implements Runnable {
	
	Process p;

	//Constructors
	UnverifiedThread() {}
	UnverifiedThread(Process newP) {p = newP;}

	public void run() {
		int q_len = 6;
		Socket sock;
		
		//Create new socket to wait for connections.
		try {
			ServerSocket unverifiedSock = new ServerSocket(p.unverifiedPort, q_len);
			while (true) {
				sock = unverifiedSock.accept();
				new UnverifiedWorker(sock, p).start();
			}
		} catch (IOException ioe) {System.out.println(ioe);}
	}
}
 
//To receive the unverified blocks and public keys sent from the peers 
class UnverifiedWorker extends Thread {
	
	Socket sock;
	Process p;

	//Constructor
	UnverifiedWorker(Socket s, Process newP) {
		sock = s;
		p = newP;
	}

	public void run() {
		PrintStream out = null;
		BufferedReader in = null;
		String msg = "";
		String process;
		String unverifiedBlock = "";
		String temp = "";

		try {
			//Input stream to be read to the server.
			in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			
			//Output stream to send to the connected clients.
			out = new PrintStream(sock.getOutputStream());

			try {
				//Read process id.
				process = in.readLine();
				int pid = Integer.parseInt(process);

				//Read the contents followed by the process id, stops when "End" is reached.
				while (!(temp = in.readLine()).equals("End")) {
					msg += temp + "\n";
				}				

				//If the public keys have not been received, the content read is the keys.
				if ((!p.peer1KeyReceived) || (!p.peer2KeyReceived)) {
					
					//Save and associate the keys with the correct peer
					//Then turn on the corresponding flag.
					if (pid == p.peer1Id) {
						p.peer1Key = p.savePublicKey(msg);
						p.peer1KeyReceived = true;
					} 
					else if (pid == p.peer2Id) {
						p.peer2Key = p.savePublicKey(msg);
						p.peer2KeyReceived = true;
					}

					//Inform the sender that the key has been received.
					out.println("Public key has been received by Process " + p.processId + " at port "
							+ p.unverifiedPort + "\n");
					out.flush();
				}

				//If the public keys have been received, then the content read is the unverified blocks.
				else {
					//If the content read starts with the XML header, then it is the qualified blocks that
					//could be added to the queue.
					if (msg.startsWith(Process.XMLHeader))
					{
						p.addUnverified(msg); 
						out.println("Unverified block has been received byProcess "+ p.processId 
								 	+ " at Port " + p.unverifiedPort + "\n");
						out.flush();
					}
					//If the message stars with "work", it means new data has been sent from the peers, 
					//start to work on the unverified blocks and update the ledger.
					else if (msg.startsWith("work"))
					{
						System.out.println("\n");
						System.out.flush();
						p.solvePuzzle();
						
						//After the ledger is updated, print the operations for user to enter.
						System.out.print("Enter your operation:\n" 
								+ "    \"R filename\" to add new data\n"
								+ "    \"L\" to list the records\n"
								+ "    \"V\" to verify the blockchain and report process credit\n"
								+ "    \"V threshold\" to verify the work threshold\n"
								+ "    \"V hash\" to verify the SHA256 string\n" 
								+ "    \"V signature\" to verify the signature\n"
								+ "    \"V datahash\" to verify the data\n"
								+ "    \"P\" to show the ledger\n"
								+ "    or \"quit\" to exit: ");

						System.out.flush();					
					}
				}
				
				//If the public key of p has not been sent yet, send the public key.
				if (!p.publicKeySent) {
					p.sendKeys(p);
				}
			}

			catch (Exception x) {
				System.out.println("Server read error");
				x.printStackTrace();
			}

			sock.close(); //Close the socket.
			
		} catch (IOException ioe) {System.out.println(ioe);}
	}
}

//A thread to receive the updated ledgers.
class BlockchainThread implements Runnable {
	
	Process p;

	//Constructors
	BlockchainThread() {}
	BlockchainThread(Process newP) {p = newP;}

	public void run() {
		int q_len = 6;
		Socket sock;

		//Create new socket to wait for connections.
		try {
			ServerSocket updatedSock = new ServerSocket(p.updatedPort, q_len);
			while (true) {
				sock = updatedSock.accept();
				new BlockchainWorker(sock, p).start();
			}
		} catch (IOException ioe) {System.out.println(ioe);}
	}
}

//To receive the updated ledgers.
class BlockchainWorker extends Thread {
	
	Socket sock;
	Process p;

	//Constructor
	BlockchainWorker(Socket s, Process newP) {
		sock = s;
		p = newP;
	}

	public void run() {
		PrintStream out = null;
		BufferedReader in = null;
		String msg = "";
		String temp;
		String process;

		try {
			//Input and output streams.
			in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			out = new PrintStream(sock.getOutputStream());

			try {

				//Get the process id.
				process = in.readLine();

				//Read the contents, in this case, read the undated ledgers.
				while (!(temp = in.readLine()).equals("End")) {
					msg += temp + "\n";
				}

				//Add the ledgers to local queue.
				p.addVerified(msg);
				out.println("Updated ledger has been received by Process " 
							+ p.processId + " at Port " + p.updatedPort);
				out.flush();
			}
			catch (IOException x) {
				System.out.println("Server read error");
				x.printStackTrace();
			}
			
			sock.close(); //Close the socket.
			
		} catch (IOException ioe) {System.out.println(ioe);}
	}
}

//A thread to handle the updates of the ledger.
class BlockLedgerThread implements Runnable {
	Process p;

	//Constructors
	BlockLedgerThread() {}
	BlockLedgerThread(Process newP) {p = newP;}

	public void run() {
		while (true) {
			new BlockWorker(p).start(); //Start the BlockWorker.
		}
	}
}

//To update the ledger and write the new ledger to disk.
class BlockWorker extends Thread {

	Process p;
	BlockWorker(Process newP) {p = newP;}

	public void run() {
		
		//If the no updated ledger in the queue, kill this thread.
		if (p.receivedLedger.peek() == null){
			Thread.currentThread().interrupt();
		}
		
		while (p.receivedLedger.peek() != null) {
			p.updateLedger(); //Update the ledger
			p.writeLedger(); //Write the ledger to disk.
		}	
	}
}

//A client thread to send connection requests.
class ClientThread implements Runnable {
	Process p;
	int port;
	String msg;

	//Constructors.
	ClientThread() {} 

	ClientThread(Process newP, int newPort, String newMsg) {
		p = newP;
		port = newPort;
		msg = newMsg;
	}

	public void run() {
		Socket sock;

		//Make connection requests.
		try {
			sock = new Socket("localhost", port);
			new ClientWorker(sock, p, msg).start();
		} catch (Exception x) {x.printStackTrace();}
	}
}

//To send messages to the connected servers
class ClientWorker extends Thread {
	Socket sock;
	Process p;
	String msg;

	//Constructor
	ClientWorker(Socket s, Process newP, String newMsg) {
		sock = s;
		p = newP;
		msg = newMsg;
	}

	public void run() {

		BufferedReader fromServer;
		PrintStream toServer;
		String textFromServer;

		try {
			//To get the response sent from the servers.
			fromServer = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			//To send to the servers.
			toServer = new PrintStream(sock.getOutputStream());

			//Send process id.
			toServer.println(p.processId);
			toServer.flush();

			//Send messages
			toServer.println(msg);
			toServer.flush();

			//Send the ending keyword "End"
			toServer.println("End");
			toServer.flush();

			//Read the response from the server, and print to console
			textFromServer = fromServer.readLine();
			if (textFromServer != null) {
				System.out.println(textFromServer);
				System.out.flush();
			}

			// System.out.println();
			// System.out.println();

			sock.close(); // Close the local socket.

		} catch (Exception e) {e.printStackTrace();}
	}
}

//Create a BlockRecord class to contain the data read from the file in XML format.
@XmlRootElement
class BlockRecord
{	
	// Fields of the data.
	private String BlockID;
	private String SignedBlockID;
	private String CreatingProcessID;
	private String TimeStamp;
	private String DataHash;
	private String Fname;
	private String Lname;
	private String SSNum;
	private String DOB;
	private String Diag;
	private String Treat;
	private String Rx;
	
	//Getters and setters of the data.
	
	public String getCBlockID() {return BlockID;} 
	@XmlElement
	public void setCBlockID(String BID) {this.BlockID = BID;} 

	public String getCSignedBlockID() {return SignedBlockID;}
	@XmlElement
	public void setCSignedBlockID(String SB) {this.SignedBlockID = SB;}

	public String getDCreatingProcess() {return CreatingProcessID;}
	@XmlElement
	public void setDCreatingProcess(String CP) {this.CreatingProcessID = CP;}

	public String getDTimeStamp() {return TimeStamp;}
	@XmlElement
	public void setDTimeStamp(String TS) {this.TimeStamp = TS;}

	public String getEDataHash() {return DataHash;}
	@XmlElement
	public void setEDataHash(String DH) {this.DataHash = DH;}

	public String getFSSNum() {return SSNum;}
	@XmlElement
	public void setFSSNum(String SS) {this.SSNum = SS;}

	public String getFFname() {return Fname;}
	@XmlElement
	public void setFFname(String FN) {this.Fname = FN;}

	public String getFLname() {return Lname;}
	@XmlElement
	public void setFLname(String LN) {this.Lname = LN;}

	public String getFDOB() {return DOB;}
	@XmlElement
	public void setFDOB(String DOB) {this.DOB = DOB;}
	
	public String getGDiag() {return Diag;}
	@XmlElement
	public void setGDiag(String D) {this.Diag = D;}

	public String getGTreat() {return Treat;}
	@XmlElement
	public void setGTreat(String D) {this.Treat = D;}

	public String getGRx() {return Rx;}
	@XmlElement
	public void setGRx(String D) {this.Rx = D;}
}
