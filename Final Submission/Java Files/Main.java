/*
 *	Cryptography Practical Project
 *  Main class by Maxfield England and Tyler Lorella
 * 	
 *  Contains I/O and arithmetic operations for key cryptographic services. 
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Scanner;

public class Main {

	final static Scanner scanner = new Scanner(System.in);

	public static void main(String[] args) {
		
		System.out.println("---Cryptography Project by Max England and Tyler Lorella---");
		System.out.println("--Enter digit for mode of operation: "
				+ "\n0-Test Vector"
				+ "\n1-Hash \n2-MAC \n3-Symmetric Encryption \n4-Symmetric Decryption "
				+ "\n5-Generate Schnorr / ECDHIES key "
				+ "\n6-Encrypt under Schnorr / ECDHIES key"
				+ "\n7-Decrypt asymmetric cryptogram"
				+ "\n8-Generate Signature"
				+ "\n9-Verify Signature");
		String mode = scanner.nextLine();

		System.out.println("--Enter digit for input method: \n"
				+ "1-File Input \n"
				+ "2-Console Input");
		String inputMethod = scanner.nextLine();


		String outputMethod = askOutputMethod();


		//1 -  Hash - 
		if (mode.equals("0")) {
			printTestVector();
		} else if (mode.equals("1")) { //Hash
			byte[] data = askForData(inputMethod);
			byte[] crypt = hashKMAC(data);
			if (outputMethod.equals("1")) {
				String folderPath = askOutputFilesLocation();
				outputFile(folderPath + "\\Hash.txt", crypt);
			} else {
				printByteData(crypt);
			}
		} else if (mode.equals("2")) { //MAC
			byte[] key = askForKey(inputMethod);
			byte[] data = askForData(inputMethod);
			byte[] crypt = macKMAC(key, data);
			if (outputMethod.equals("1")) {
				String folderPath = askOutputFilesLocation();
				outputFile(folderPath + "\\MAC.txt", crypt);
			} else {
				printByteData(crypt);
			}
		} else if (mode.equals("3")) { //Symmetric Encryption
			byte[] key = askForKey(inputMethod);
			byte[] data = askForData(inputMethod);
			symmetricEncryption(key, data, outputMethod);
		} else if (mode.equals("4")) { //Symmetric Decryption
			byte[] cryptogram = askForCryptogram(inputMethod);
			byte[] key = askForKey(inputMethod);

			//Retrieve z, c, t from cryptogram file
			byte[] z = new byte[64];			
			byte[] c = new byte[cryptogram.length-128];
			byte[] t = new byte[64];
			for (int i = 0; i < 64; i++) z[i] = cryptogram[i];
			for (int i = 64; i < cryptogram.length - 64; i++) c[i-64] = cryptogram[i];
			for (int i = cryptogram.length - 64; i < cryptogram.length; i++) t[i - (cryptogram.length - 64)] = cryptogram[i];

			//Retrieve message
			byte[] message = symmetricDecryption(z, key, c, t);
			if (outputMethod.equals("1")) {
				String folderPath = askOutputFilesLocation();
				outputFile(folderPath + "\\DecryptedMessage.txt", message);
			} else {
				printByteData(message);
			}
		} else if (mode.equals("5")) { //Generate key pair
			byte[] key = askForKey(inputMethod);
			Point result = getKey(key);
			if (outputMethod.equals("1")) {
				String folderPath = askOutputFilesLocation();
				outputFile(folderPath + "\\Point.txt", result.toByte());
			} else {
				printByteData(result.toByte());
			}
		} else if (mode.equals("6")) { //pub encrypt
			byte[] stuff = askForPoint(inputMethod);
			byte[] x = new byte[stuff.length - 1];

			for (int index = 0; index < x.length; index++) {
				x[index] = stuff[index];
			}
			boolean isEven = stuff[stuff.length - 1] == 1;

			Point pointV = new Point(new BigInteger(x), isEven);

			byte[] data = askForData(inputMethod);
			pubEncrypt(pointV, data, outputMethod);
		} else if (mode.equals("7")) { //pub decrypt

			byte[] cryptogram = askForCryptogram(inputMethod);
			
			byte[] pointBytes = new byte[67];
			for (int i = 0; i < 67; i++) {
				pointBytes[i] = cryptogram[i];
			}
			byte[] x = new byte[pointBytes.length - 1];

			for (int index = 0; index < x.length; index++) {
				x[index] = pointBytes[index];
			}
			boolean isEven = pointBytes[pointBytes.length - 1] == 1;
			Point Z = new Point(new BigInteger(x), isEven);
			byte[] t = new byte[64];
			byte[] c = new byte[cryptogram.length-t.length-pointBytes.length];
			for (int i = 67; i < cryptogram.length - 64; i++) c[i-67] = cryptogram[i];
			for (int i = cryptogram.length - 64; i < cryptogram.length; i++) t[i - (cryptogram.length - 64)] = cryptogram[i];

			byte[] key = askForKey(inputMethod);
			byte[] message = pubDecrypt(key, Z, c, t);

			if (outputMethod.equals("1")) {
				String folderPath = askOutputFilesLocation();
				outputFile(folderPath + "\\DecryptedMessage.txt", message);
			} else {
				printByteData(message);
			}
		} else if (mode.equals("8")) {
			byte[] data = askForData(inputMethod);
			byte[] key = askForKey(inputMethod);
			byte[] signature = signatureGen(data, key);

			if (outputMethod.equals("1")) {
				String folderPath = askOutputFilesLocation();
				outputFile(folderPath + "\\Signature.txt", signature);
			} else {
				printByteData(signature);
			}
		} else if (mode.equals("9")) {
			byte[] signature = askForSignature(inputMethod);
			byte[] data = askForData(inputMethod);

			byte[] stuff = askForPoint(inputMethod);
			byte[] x = new byte[stuff.length - 1];

			for (int index = 0; index < x.length; index++) {
				x[index] = stuff[index];
			}
			boolean isEven = stuff[stuff.length - 1] == 1;
			Point V = new Point(new BigInteger(x), isEven);

			boolean result = signatureVerify(signature, data, V);
			if (result) System.out.println("SIGNATURE ACCEPTED");
			else System.out.println("SIGNATURE REJECTED");
		}


		scanner.close();
		System.out.println("---Done!---");
	}

	/* ------------------------------------------
	 * 			Modes of Operation Methods
	 * ------------------------------------------*/

	/**
	 * Test vector for comparison to expected KMAC output
	 */
	private static void printTestVector() {
		System.out.println("--------Test Vector Start-------");
		byte[] testData = {00, 01, 00, 11};
		byte[] testKey = {0b0};
		String diveyString = "Email Signature";
		KMACXOF256 kmac = new KMACXOF256(testKey, testData, 256, diveyString);
		byte[] result = kmac.getData();
		System.out.println("Bytes of data: " + result.length);
		printByteData(result);
		System.out.println("--------Test Vector End-------");
	}

	/**
	 * Provide a hash of the given data, via KMACXOF256.
	 * @param data The byte array of data to hash.
	 * @return The hashed data
	 */
	private static byte[] hashKMAC(byte[] data) {
		String key = "";
		KMACXOF256 sponge = new KMACXOF256(key.getBytes(), data, 512, "D"); 
		return sponge.getData();
	}

	/**
	 * Provide a keyed message authentication code of the given data, via KMACXOF256.
	 * @param key The MAC key.
	 * @param data The data for which to provide a MAC.
	 * @return a pseudo-unique 512-bit hash of the key and data. 
	 */
	private static byte[] macKMAC(byte[] key, byte[] data) {
		KMACXOF256 sponge = new KMACXOF256(key, data, 512, "T");
		return sponge.getData();
	}

	/**
	 * Create a symmetric encryption of the given file under the given key, using KMACXOF256 for
	 * extendible hashing.
	 * @param key The key as a byte array.
	 * @param data The message as a byte array.
	 * @param outputChoice Provided output option; console or file writing.
	 */
	private static void symmetricEncryption(byte[] key, byte[] data, String outputChoice) {
		//getting a random 512 bit value
		SecureRandom secureRandom = new SecureRandom();
		byte[] initializationValue = new byte[64];
		secureRandom.nextBytes(initializationValue);

		//
		byte[] keka = (new KMACXOF256(concatinateBytes(initializationValue, key)
				, ("").getBytes(), 1024, "S")).getData(); 
		byte[] ke = new byte[keka.length/2];
		byte[] ka = new byte[keka.length/2];

		for (int index = 0; index < keka.length/2; index++) {
			ke[index] = keka[index];
		}
		for (int index = keka.length/2; index < keka.length; index++) {
			ka[index - keka.length/2] = keka[index]; 
		}

		//encrypted message
		byte[] c = xorBytes((new KMACXOF256(ke, ("").getBytes(), data.length * 8, "SKE")).getData(), data);
		//MAC
		byte[] t = (new KMACXOF256(ka, data, 512, "SKA")).getData();

		//Populate the cryptogram: cryptogram = (z | c | t)
		byte[] cryptogram = new byte[initializationValue.length + c.length + t.length];
		int curr = 0;
		for (int i = 0; i < initializationValue.length; i++) {
			cryptogram[curr++] = initializationValue[i];
		}
		for (int i = 0; i < c.length; i++) {
			cryptogram[curr++] = c[i];
		}
		for (int i = 0; i < t.length; i++) {
			cryptogram[curr++] = t[i];
		}

		if (outputChoice.equals("1")) {
			String folderPath = askOutputFilesLocation();
			outputFile(folderPath + "\\cryptogram.txt", cryptogram);
		} else { 
			System.out.print("\nc: ");
			printByteData(cryptogram);
		}
	}

	/**
	 * Decrypts a cryptogram created by the symmetric encryption.
	 * 
	 * @param iv The random value used for encryption as derived from the cryptogram.
	 * @param key The provided key as used in encryption.
	 * @param c The ciphertext as derived from the cryptogram.
	 * @param t The message authentication code as derived from the cryptogram.
	 * @return The decrypted data as a byte array.
	 */
	private static byte[] symmetricDecryption(byte[] iv, byte[] key, byte[] c, byte[] t) {
		byte[] keka = (new KMACXOF256(concatinateBytes(iv, key), ("").getBytes(), 1024, "S")).getData(); 
		byte[] ke = new byte[keka.length/2];
		byte[] ka = new byte[keka.length/2];

		for (int index = 0; index < keka.length/2; index++) {
			ke[index] = keka[index];
		}
		for (int index = keka.length/2; index < keka.length; index++) {
			ka[index - keka.length/2] = keka[index]; 
		}

		byte[] m = xorBytes((new KMACXOF256(ke, ("").getBytes(), c.length * 8, "SKE")).getData(), c);
		byte[] tPrime = (new KMACXOF256(ka, m, 512, "SKA")).getData();

		if (equalByteArrays(tPrime, t)) {
			System.out.println("MESSAGE AUTHENTICITY ACCEPTED");
			return m;
		} else {
			System.out.println("MESSAGE AUTHENTICITY REJECTED");
			return null;
		}
	}

	/**
	 * Creates a point from the provided password along the Edwards curve E521.
	 * 
	 * @param pw The password for which to generate a key.
	 * @return The point generated. 
	 */
	private static Point getKey(byte[] pw) {

		byte[] secretBytes = (new KMACXOF256(pw, "".getBytes(), 512, "K").getData());

		BigInteger s = new BigInteger(secretBytes);
		s = s.multiply(BigInteger.valueOf(4));

		Point V = Point.multiply(Point.G, s);

		return V;
	}
	
	/**
	 * Encrypt using ECDH protocol and KMACXOF256 for extendible hashing, either to file or directly
	 * to console. Creates a combined cryptogram including a random point on the Edwards curve E521, the ciphertext,
	 * and a MAC. 
	 * 
	 * @param V The 'key' EC point to be used as key for encryption
	 * @param m the message (as a byte array) to encrypt
	 * @param outputChoice The provided mode of output; either to console or to file.
	 */
	private static void pubEncrypt(Point V, byte[] m, String outputChoice) {

		SecureRandom secureRandom = new SecureRandom();
		byte[] randomVals = new byte[64];

		BigInteger k = BigInteger.ZERO;
		Point W;
		
		//k = new random; k = 4k
		secureRandom.nextBytes(randomVals);
		k = new BigInteger(randomVals);
		k = k.multiply(BigInteger.valueOf(4));

		//W = kV
		W = Point.multiply(V, k);
		
		//Z = kG
		Point Z = Point.multiply(Point.G, k);
		
		//ke||ka = KMACXOF256(Wx, "", 1024, "P")
		byte[] keka = (new KMACXOF256(W.getX().toByteArray(), ("").getBytes(), 1024, "P")).getData(); 

		byte[] ke = new byte[keka.length/2];
		byte[] ka = new byte[keka.length/2];
		for (int index = 0; index < keka.length/2; index++) {
			ke[index] = keka[index];
		}
		for (int index = keka.length/2; index < keka.length; index++) {
			ka[index - keka.length/2] = keka[index]; 
		}

		byte[] mask = new KMACXOF256(ke, "".getBytes(), m.length * 8, "PKE").getData();
		byte[] c = xorBytes(m, mask);
		byte[] t = new KMACXOF256(ka, m, 512, "PKA").getData();
		byte[] zBytes = Z.toByte();

		//Populate the cryptogram: cryptogram = (z | c | t)
		byte[] cryptogram = new byte[zBytes.length + c.length + t.length];
		int curr = 0;

		for (int i = 0; i < zBytes.length; i++) {
			cryptogram[curr++] = zBytes[i];
		}
		for (int i = 0; i < c.length; i++) {
			cryptogram[curr++] = c[i];
		}
		for (int i = 0; i < t.length; i++) {
			cryptogram[curr++] = t[i];
		}
		
		
		if (outputChoice.equals("1")) {
			String folderPath = askOutputFilesLocation();
			outputFile(folderPath + "\\cryptogram.txt", cryptogram);
			//			outputFile(folderPath + "\\z.txt", Z.toByte());
			//			outputFile(folderPath + "\\c.txt", c);
			//			outputFile(folderPath + "\\t.txt", t);
		} else { 
			System.out.print("\ncryptogram: ");
			printByteData(cryptogram);
			//			System.out.print("\nz: ");
			//			printByteData(Z.toByte());
			//			System.out.print("\nc: ");
			//			printByteData(c);
			//			System.out.print("\nt: ");
			//			printByteData(t);
		}

	}

	/**
	 * Decrypts the generated cryptogram, given the random point, ciphertext, MAC, and the password.
	 * @param pw The password used to generate point V.
	 * @param Z A point factored with the random value generated in the encryption.
	 * @param c The ciphertext of the desired message.
	 * @param t The MAC pulled from the cryptogram, to be compared.
	 * @return The deciphered message.
	 */
	private static byte[] pubDecrypt(byte[] pw, Point Z, byte[] c, byte[] t) {
		BigInteger s = new BigInteger(new KMACXOF256(pw, "".getBytes(), 512, "K").getData());
		s = s.multiply(BigInteger.valueOf(4));

		Point W = Point.multiply(Z, s);

		byte[] keka = (new KMACXOF256(W.getX().toByteArray(), ("").getBytes(), 1024, "P")).getData(); 
		
		byte[] ke = new byte[keka.length/2];
		byte[] ka = new byte[keka.length/2];
		for (int index = 0; index < keka.length/2; index++) {
			ke[index] = keka[index];
		}
		for (int index = keka.length/2; index < keka.length; index++) {
			ka[index - keka.length/2] = keka[index]; 
		}

		byte[] mask = new KMACXOF256(ke, "".getBytes(), c.length * 8, "PKE").getData();
		byte[] m = xorBytes(c, mask);
		byte[] t2 = new KMACXOF256(ka, m, 512, "PKA").getData();

		//if t = t2, return c; otherwise the message is not valid :(
		boolean equiv = true;
		if (t.length != t2.length) equiv = false;
		for (int i = 0; i < t.length; i++) {
			if (t[i] != t2[i]) equiv = false;
		}

		
		if (equiv) {
			System.out.println("OUTPUT ACCEPTED");
			return m;
		}
		else {
			System.out.println("OUTPUT UNACCEPTABLE");
			return m;
		}
	}

	/**
	 * Generates a digital signature from the message and private key.
	 * @param m The message to be signed.
	 * @param pw The private key.
	 * @return A byte array containing the generated digital signature.
	 */
	private static byte[] signatureGen(byte[] m, byte[] pw){

		BigInteger s = new BigInteger(new KMACXOF256(pw, "".getBytes(), 512, "K").getData());
		s = s.multiply(BigInteger.valueOf(4));

		BigInteger k = new BigInteger(new KMACXOF256(s.toByteArray(), m, 512, "N").getData());
		k = k.multiply(BigInteger.valueOf(4));

		Point U = Point.multiply(Point.G, k);
		
		BigInteger h = new BigInteger(new KMACXOF256(U.getX().toByteArray(), m, 512, "T").getData());
		BigInteger z = k.subtract(h.multiply(s)).mod(Point.r);

		return (concatinateBytes(h.toByteArray(), z.toByteArray()));
	}

	/**
	 * Verify a digital signature without receiving the private key used to sign.
	 * @param hz The digital signature as provided. 
	 * @param m The data signed by digital signature.
	 * @param V A point on E521 generated using the private key.
	 * @return true if the signature can be verified; false otherwise.
	 */
	private static boolean signatureVerify(byte[] hz, byte[] m, Point V) {

		byte[] h = new byte[64];
		byte[] z = new byte[hz.length -64];
		for (int i = 0; i < h.length; i++) {
			h[i] = hz[i];
		}
		for (int i = 0; i < z.length; i++) {
			z[i] = hz[64+i];
		}

		BigInteger hVal = new BigInteger(h);
		BigInteger zVal = new BigInteger(z);

		Point hV = Point.multiply(V, hVal);
		Point zG = Point.multiply(Point.G, zVal);
		
		Point U = Point.pointSum(hV, zG);
		BigInteger uX = U.getX();
		byte[] test = new KMACXOF256(uX.toByteArray(), m, 512, "T").getData();

		boolean ret = true;
		if (test.length != h.length) ret = false;
		for (int i = 0; i < h.length; i++) {
			if (h[i] != test[i]) ret = false;
		}

		return ret;
	}


	/* ------------------------------------------
	 * 			Input Assistance Methods
	 * ------------------------------------------*/

	/**
	 * To deprecate askForIV, askForMAC, one instance of askForData; combining all encryption output data to one file
	 * @param inputChoice Whether the user is entering from file or straight to console.
	 * @return The cryptogram as a byte array retrieved from the user.
	 */
	private static byte[] askForCryptogram(String inputChoice) {
		System.out.println();
		if (inputChoice.equals("1")) {
			System.out.print("Enter cryptogram filename: ");
			return getFileInput();
		} else {
			System.out.print("Enter cryptogram: ");
			return getConsoleInput();
		}
	}

	//	private static byte[] askForIV(String inputChoice) {
	//		System.out.println();
	//		if (inputChoice.equals("1")) {
	//			System.out.print("Enter IV filepath: ");
	//			return getFileInput();
	//		} else {
	//			System.out.print("Enter IV: ");
	//			return getConsoleInput();
	//		}
	//	}

	/**
	 * Retrieves a key from the user.
	 * @param inputChoice Whether the user is providing a key by file or by console.
	 * @return The key as a byte array.
	 */
	private static byte[] askForKey(String inputChoice) {
		System.out.println();
		if (inputChoice.equals("1")) {
			System.out.print("Enter key filename: ");
			return getFileInput();
		} else {
			System.out.print("Enter key: ");
			return getConsoleInput();
		}
	}

	/**
	 * Retrieves a message from the user.
	 * @param inputChoice Whether the user is providing the message data by file or by console.
	 * @return The message as a byte array.
	 */
	private static byte[] askForData(String inputChoice) {
		System.out.println();
		if (inputChoice.equals("1")) {
			System.out.print("Enter message filename: ");
			return getFileInput();
		} else {
			System.out.print("Enter data: ");
			return getConsoleInput();
		}
	}

	//	private static byte[] askForMAC(String inputChoice) {
	//		System.out.println();
	//		if (inputChoice.equals("1")) {
	//			System.out.print("Enter MAC filepath: ");
	//			return getFileInput();
	//		} else {
	//			System.out.print("Enter mac: ");
	//			return getConsoleInput();
	//		}
	//	}

	/**
	 * Retrieves a point from the user.
	 * @param inputChoice Whether the user is providing the point data by file or text.
	 * @return A byte array containing point data (x val + y bit as byte array) 
	 */
	private static byte[] askForPoint(String inputChoice) {
		System.out.println();
		if (inputChoice.equals("1")) {
			System.out.print("Enter Point filepath: ");
			return getFileInput();

		} else {
			System.out.print("Enter Point: ");
			return getConsoleInput();
		}
	}

	/**
	 * Retrieves signature from user input.
	 * @param inputChoice Whether the user provides the signature as a file or console input.
	 * @return Byte array containing the digital signature.
	 */
	private static byte[] askForSignature(String inputChoice) {
		System.out.println();
		if (inputChoice.equals("1")) {
			System.out.print("Enter Signature filepath: ");
			return getFileInput();

		} else {
			System.out.print("Enter Signature: ");
			return getConsoleInput();
		}
	}

	/**
	 * Retrieve input from the console, and return it as a byte array.
	 * @return A byte array containing input received from the user.
	 */
	private static byte[] getConsoleInput() {
		//Scanner scanner = new Scanner(System.in);
		String stringInput = scanner.nextLine();
		//scanner.close();
		return stringInput.getBytes();
	}

	/**
	 * Retrieve input from a provided file path, and return it as a byte array.
	 * @return A byte array containing the contents of a file.
	 */
	private static byte[] getFileInput() {
		//System.out.print("Enter file path: ");
		//Scanner scanner = new Scanner(System.in);
		ArrayList<Byte> arrayData = new ArrayList<Byte>();
		String filePath = scanner.nextLine();
		try {
			
			FileInputStream fileInput = new FileInputStream(filePath);
			byte[] fileByte = new byte[1];
			while (true) { //assumption that the input file will always contain at least 1 byte of data
				int guard = fileInput.read(fileByte);
				if (guard == -1) break;
				arrayData.add(fileByte[0]);
			}
			
			fileInput.close();
		} catch (Exception e) {
			System.out.println("Invalid file input, Exiting Program");
			System.exit(0);
		}
		
		byte[] fileData = new byte[arrayData.size()];
		
		for (int i = 0; i < arrayData.size(); i++) {
			fileData[i] = arrayData.get(i);
		}

		return fileData;
	}


	/* ------------------------------------------
	 * 			Output Assistance Methods
	 * ------------------------------------------*/

	/**
	 * Asks the user for output preference.
	 * @return The user's choice as a string.
	 */
	private static String askOutputMethod() {
		System.out.println("How would you like to output the results?\n"
				+ "1-File Output \n2-Console Outut");
		return scanner.nextLine();
	}

	/**
	 * Asks the user for folder path.
	 * @return User's input for filepath.
	 */
	private static String askOutputFilesLocation() {
		System.out.println("Output folder path : ");
		return scanner.nextLine();
	}

	/**
	 * Writes a file to the given filepath, or else throws an exception.
	 * @param filePath The location to which the file should be written.
	 * @param data The data to write to file.
	 */
	private static void outputFile(String filePath, byte[] data) {
		try {
			FileOutputStream writer = new FileOutputStream(new File(filePath));
			writer.write(data);
			writer.close();
		} catch (FileNotFoundException e) {
			System.out.println("invalid file location");
			e.printStackTrace();
			System.exit(0);
		} catch (IOException e) {
			System.out.println("invalid print");
			e.printStackTrace();
			System.exit(0);
		}
	}


	/* ------------------------------------------
	 * 				Auxiliary Methods
	 * ------------------------------------------*/

	/**
	 * Compares two byte arrays for equality.
	 * @param data1 The first byte array.
	 * @param data2 The second byte array.
	 * @return True if the byte arrays are of equal lengths and all contents are equal; false otherwise.
	 */
	private static boolean equalByteArrays(byte[] data1, byte[] data2) {
		if (data1.length != data2.length) return false;
		for (int index = 0; index < data1.length; index++) {
			if (data1[index] != data2[index]) return false;
		}
		return true;
	}

	/**
	 * Performs the exclusive-or operation between same-index bytes on two byte arrays, and returns
	 * an array containing the results.
	 * @param data1 The first byte array to . 
	 * @param data2 The second byte array.
	 * @return A byte array containing the exclusive-or products of matching bytes in both arrays.
	 */
	private static byte[] xorBytes(byte[] data1, byte[] data2) {
		if (data1.length != data2.length) System.out.println(data1.length + " != " + data2.length);
		byte[] result = new byte[data1.length];
		for (int index = 0; index < data1.length; index++) {
			result[index] = (byte) (data1[index] ^ data2[index]);
		}
		return result;
	}

	/**
	 * Combines two byte arrays into a single byte array.
	 * @param data1 The data that appears first in the combined byte array.
	 * @param data2 The data that appears last in the combined byte array.
	 * @return A single array containing the elements of both provided arrays.
	 */
	private static byte[] concatinateBytes(byte[] data1, byte[] data2) {
		byte[] toReturn = new byte[data1.length + data2.length];
		int indexCounter = 0;
		for (byte element: data1) {
			toReturn[indexCounter++] = element; 
		}
		for (byte element: data2) {
			toReturn[indexCounter++] = element; 
		}
		return toReturn;
	}

	/**
	 * Prints the contents of the provided byte array for readability to the console.
	 * @param data The byte array to be printed and made visible to the user.
	 */
	private static void printByteData(byte[] data) {
		String toBitString = "";
		for (int index = 0; index < data.length; index++) {
			toBitString = toBitString + " " + byte2String(data[index]);
		}
		System.out.println("Result: " + toBitString);
	}

	/**
	 * Converts an arraylist of bytes to an unwrapped byte array.
	 * @param input The arraylist to convert to a byte array.
	 * @return  An array of primitive bytes equivalent to the provided arraylist.
	 */
	@SuppressWarnings("unused")
	private static byte[] convertToArray(ArrayList<Byte> input) {
		byte[] toReturn = new byte[input.size()];
		for (int index = 0; index < input.size(); index++) {
			toReturn[index] = input.get(index);
		}
		return toReturn;
	}

	/**
	 * Writes a byte to a bitstring.
	 * @param toConvert The byte to be presented as a string of bits.
	 * @return A string representation of the byte.
	 */
	private static String byte2String(byte toConvert) {
		String toReturn = "";

		byte byteMask = 0b0000001;

		for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
			int bit = byteMask & toConvert;
			if (bit == 0) toReturn = "0" + toReturn;
			else toReturn = "1" + toReturn;
			byteMask = (byte) (byteMask * 2);
		}

		return toReturn;
	}

}
