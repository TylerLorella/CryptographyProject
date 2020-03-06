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

		System.out.println("---Cryptography Project by Max England, and Tyler Lorella---");
		System.out.println("--Enter digit for mode of operation: "
				+ "\n0-Test Vector"
				+ "\n1-Hash \n2-MAC \n3-Symmetric Encryption \n4-Symmetric Decryption "
				+ "\n5-Generate Schnorr / ECDHIES key "
				+ "\n6-Encrypt under Schnorr / ECDHIES key"
				+ "\n7-Decrypt cryptogram"
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
			byte[] z = askForIV(inputMethod);
			byte[] key = askForKey(inputMethod);
			byte[] c = askForData(inputMethod);
			byte[] t = askForMAC(inputMethod);
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
			System.out.println("Last bit : " + stuff[stuff.length-1]);
			
			Point pointV = new Point(new BigInteger(x), isEven);
			
			byte[] data = askForData(inputMethod);
			pubEncrypt(pointV, data, outputMethod);
		} else if (mode.equals("7")) { //pub decrypt
			byte[] stuff = askForPoint(inputMethod);
			byte[] x = new byte[stuff.length - 1];
			
			for (int index = 0; index < x.length; index++) {
				x[index] = stuff[index];
			}
			boolean isEven = stuff[stuff.length - 1] == 1;
			Point Z = new Point(new BigInteger(x), isEven);
			
			byte[] key = askForKey(inputMethod);
			byte[] c = askForData(inputMethod);
			byte[] t = askForMAC(inputMethod);
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
			if (result) System.out.println("SIGNATURE ACCECPTABLE");
			else System.out.println("SIGNATURE UNACCECPTABLE");
		}


		scanner.close();
		System.out.println("---Done!---");
	}


	/* ------------------------------------------
	 * 			Modes of Operation Methods
	 * ------------------------------------------*/

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

	private static byte[] hashKMAC(byte[] data) {
		String key = "";
		KMACXOF256 sponge = new KMACXOF256(key.getBytes(), data, 512, "D"); 
		return sponge.getData();
	}

	private static byte[] macKMAC(byte[] key, byte[] data) {
		KMACXOF256 sponge = new KMACXOF256(key, data, 512, "T");
		return sponge.getData();
	}

	private static void symmetricEncryption(byte[] key, byte[] data, String outputChoice) {
		//getting a random 512 bit value
		SecureRandom secureRandom = new SecureRandom();
		byte[] initializationValue = new byte[64];
		secureRandom.nextBytes(initializationValue);

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

		if (outputChoice.equals("1")) {
			String folderPath = askOutputFilesLocation();
			outputFile(folderPath + "\\z.txt", initializationValue);
			outputFile(folderPath + "\\c.txt", c);
			outputFile(folderPath + "\\t.txt", t);
		} else { 
			System.out.print("\nz: ");
			printByteData(initializationValue);
			System.out.print("\nc: ");
			printByteData(c);
			System.out.print("\nt: ");
			printByteData(t);
		}
	}

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
			System.out.println("OUTPUT ACCEPTED");
			return m;
		} else {
			System.out.println("OUTPUT UNACCEPTABLE");
			return m;
		}
	}

	private static Point getKey(byte[] pw) {

		byte[] secretBytes = (new KMACXOF256(pw, "".getBytes(), 512, "K").getData());

		BigInteger s = new BigInteger(secretBytes);
		s = s.multiply(BigInteger.valueOf(4));

		BigInteger newX = Point.G.getX().multiply(s);
		BigInteger newY = Point.G.getY().multiply(s);

		Point V = new Point(newX, newY);

		return V;
	}

	private static void pubEncrypt(Point V, byte[] m, String outputChoice) {

		SecureRandom secureRandom = new SecureRandom();
		byte[] randomVals = new byte[64];
		secureRandom.nextBytes(randomVals);

		BigInteger k = new BigInteger(randomVals);
		k = k.multiply(BigInteger.valueOf(4));

		BigInteger newX =  k.multiply(V.getX());
		BigInteger newY = k.multiply(V.getY());

		Point W = new Point(newX, newY);

		BigInteger zX = k.multiply(Point.G.getX());
		BigInteger zY = k.multiply(Point.G.getY());

		Point Z = new Point(zX, zY);

		byte[] keka = (new KMACXOF256(W.getX().toByteArray(), ("").getBytes(), 1024, "P")).getData(); 
		byte[] ke = new byte[keka.length/2];
		byte[] ka = new byte[keka.length/2];
		for (int index = 0; index < keka.length/2; index++) {
			ke[index] = keka[index];
		}
		for (int index = keka.length/2; index < keka.length; index++) {
			ka[index - keka.length/2] = keka[index]; 
		}

		byte[] mask = new KMACXOF256(ke, "".getBytes(), m.length, "PKE").getData();
		byte[] c = xorBytes(m, mask);
		byte[] t = new KMACXOF256(ka, m, 512, "PKA").getData();

		if (outputChoice.equals("1")) {
			String folderPath = askOutputFilesLocation();
			outputFile(folderPath + "\\z.txt", Z.toByte());
			outputFile(folderPath + "\\c.txt", c);
			outputFile(folderPath + "\\t.txt", t);
		} else { 
			System.out.print("\nz: ");
			printByteData(Z.toByte());
			System.out.print("\nc: ");
			printByteData(c);
			System.out.print("\nt: ");
			printByteData(t);
		}
		
	}

	private static byte[] pubDecrypt(byte[] pw, Point Z, byte[] c, byte[] t) {
		BigInteger s = new BigInteger(new KMACXOF256(pw, "".getBytes(), 512, "K").getData());
		s = s.multiply(BigInteger.valueOf(4));

		BigInteger wX = s.multiply(Z.getX());
		BigInteger wY = s.multiply(Z.getY());

		Point W = new Point(wX, wY);

		byte[] keka = (new KMACXOF256(W.getX().toByteArray(), ("").getBytes(), 1024, "P")).getData(); 
		byte[] ke = new byte[keka.length/2];
		byte[] ka = new byte[keka.length/2];
		for (int index = 0; index < keka.length/2; index++) {
			ke[index] = keka[index];
		}
		for (int index = keka.length/2; index < keka.length; index++) {
			ka[index - keka.length/2] = keka[index]; 
		}

		byte[] mask = new KMACXOF256(ke, "".getBytes(), c.length, "PKE").getData();
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
			return null;
		}
	}

	private static byte[] signatureGen(byte[] m, byte[] pw){

		BigInteger s = new BigInteger(new KMACXOF256(pw, "".getBytes(), 512, "K").getData());
		s.multiply(BigInteger.valueOf(4));

		BigInteger k = new BigInteger(new KMACXOF256(s.toByteArray(), m, 512, "N").getData());
		k.multiply(BigInteger.valueOf(4));

		BigInteger uX = k.multiply(Point.G.getX());

		BigInteger h = new BigInteger(new KMACXOF256(uX.toByteArray(), m, 512, "T").getData());
		BigInteger z = k.subtract(h.multiply(s)).mod(Point.r);

		return (concatinateBytes(h.toByteArray(), z.toByteArray()));

	}

	private static boolean signatureVerify(byte[] hz, byte[] m, Point V) {

		byte[] h = new byte[512];
		byte[] z = new byte[hz.length -512];
		for (int i = 0; i < h.length; i++) {
			h[i] = hz[i];
		}
		for (int i = 0; i < z.length; i++) {
			z[i] = hz[512+i];
		}

		BigInteger hVal = new BigInteger(h);
		BigInteger zVal = new BigInteger(z);

		BigInteger uX = zVal.multiply(Point.G.getX()).add(hVal.multiply(V.getX()));
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

	private static byte[] askForIV(String inputChoice) {
		System.out.println();
		if (inputChoice.equals("1")) {
			System.out.print("Enter IV filepath: ");
			return getFileInput();
		} else {
			System.out.print("Enter IV: ");
			return getConsoleInput();
		}
	}

	private static byte[] askForKey(String inputChoice) {
		System.out.println();
		if (inputChoice.equals("1")) {
			System.out.print("Enter key filepath: ");
			return getFileInput();
		} else {
			System.out.print("Enter key: ");
			return getConsoleInput();
		}
	}

	private static byte[] askForData(String inputChoice) {
		System.out.println();
		if (inputChoice.equals("1")) {
			System.out.print("Enter data filepath: ");
			return getFileInput();
		} else {
			System.out.print("Enter data: ");
			return getConsoleInput();
		}
	}

	private static byte[] askForMAC(String inputChoice) {
		System.out.println();
		if (inputChoice.equals("1")) {
			System.out.print("Enter MAC filepath: ");
			return getFileInput();
		} else {
			System.out.print("Enter mac: ");
			return getConsoleInput();
		}
	}

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
	
	private static byte[] getConsoleInput() {
		//Scanner scanner = new Scanner(System.in);
		String stringInput = scanner.nextLine();
		//scanner.close();
		return stringInput.getBytes();
	}

	private static byte[] getFileInput() {
		//System.out.print("Enter file path: ");
		//Scanner scanner = new Scanner(System.in);
		byte[] fileData = {0b0};
		String filePath = scanner.nextLine();
		try {
			ArrayList<Byte> arrayData = new ArrayList<Byte>();
			FileInputStream fileInput = new FileInputStream(filePath);
			byte section = 0b0;
			while (section != -1) {
				section = (byte) fileInput.read();
				if (section == -1) break;
				arrayData.add(section);
			}
			fileData = convertToArray(arrayData);
			fileInput.close();
		} catch (Exception e) {
			System.out.println("Invalid file input, Exiting Program");
			System.exit(0);
		}
		System.out.println();
		//scanner.close();
		return fileData;
	}


	/* ------------------------------------------
	 * 			Output Assistance Methods
	 * ------------------------------------------*/

	private static String askOutputMethod() {
		System.out.println("How would you like to output the results?\n"
				+ "1-File Output \n2-Console Outut");
		return scanner.nextLine();
	}

	private static String askOutputFilesLocation() {
		System.out.println("Output folder path : ");
		return scanner.nextLine();
	}

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

	
	private static boolean equalByteArrays(byte[] data1, byte[] data2) {
		if (data1.length != data2.length) return false;
		for (int index = 0; index < data1.length; index++) {
			if (data1[index] != data2[index]) return false;
		}
		return true;
	}

	private static byte[] xorBytes(byte[] data1, byte[] data2) {
		if (data1.length != data2.length) System.out.println(data1.length + " != " + data2.length);
		byte[] result = new byte[data1.length];
		for (int index = 0; index < data1.length; index++) {
			result[index] = (byte) (data1[index] ^ data2[index]);
		}
		return result;
	}

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

	private static void printByteData(byte[] data) {
		String toBitString = "";
		for (int index = 0; index < data.length; index++) {
			toBitString = toBitString + " " + byte2String(data[index]);
		}
		System.out.println("Result: " + toBitString);
	}

	private static byte[] convertToArray(ArrayList<Byte> input) {
		byte[] toReturn = new byte[input.size()];
		for (int index = 0; index < input.size(); index++) {
			toReturn[index] = input.get(index);
		}
		return toReturn;
	}


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
