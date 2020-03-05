import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Scanner;

public class Main {

	public static void main(String[] args) {

		System.out.println("---Cryptography Project by Max England, and Tyler Lorella---");
		System.out.println("--Enter digit for mode of operation: "
				+ "\n0-Test Vector"
				+ "\n1-Hash \n2-MAC \n3-Symmetric Encryption \n4-Symmetric Decryption "
				+ "\n5-Generate Schnorr / ECDHIES key "
				+ "\n6-Encrypt under Schnorr / ECDHIES key"
				+ "\n7-Decrypt cryptogram");
		Scanner scanner = new Scanner(System.in);
		String mode = scanner.nextLine();
		
		
		System.out.println("--Enter digit for input method: "
				+ "1-File Input \n"
				+ "2-Console Input");
		String inputMethod = scanner.nextLine();
		scanner.close();
		
		//modes
		//1 -  Hash - 
		if (mode.equals("0")) {
			printTestVector();
	 	} else if (mode.equals("1")) {
			byte[] data = askForData(inputMethod);
			byte[] crypt = hashKMAC(data);
			printByteData(crypt);
		} else if (mode.equals("2")) {
			byte[] key = askForKey(inputMethod);
			byte[] data = askForData(inputMethod);
			byte[] crypt = macKMAC(key, data);
			printByteData(crypt);
		} else if (mode.equals("3")) {
			
		}
	}
	
	
	/* ------------------------------------------
	 * 			Modes of Operation Methods
	 * ------------------------------------------*/
	
	private static void printTestVector() {
		System.out.println("--------Test Vector Start-------");
		byte[] testData = {00, 01, 00, 11};
		byte[] testKey = {0b0};
		String diveyString = "Email Signature";
		KMACXOF256 kmac = new KMACXOF256(testKey, testData, 1, diveyString);
		printByteData(kmac.getData());
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

	/* ------------------------------------------
	 * 			Input Assistance Methods
	 * ------------------------------------------*/
	
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
	
	private static byte[] getConsoleInput() {
		Scanner scanner = new Scanner(System.in);
		String stringInput = scanner.nextLine();
		scanner.close();
		return stringInput.getBytes();
	}
	
	private static byte[] getFileInput() {
		//System.out.print("Enter file path: ");
		Scanner scanner = new Scanner(System.in);
		byte[] fileData = {0b0};
		String filePath = scanner.nextLine();
		try {
			ArrayList<Byte> arrayData = new ArrayList<Byte>();
			FileInputStream fileInput = new FileInputStream(filePath);
			byte section = 0b0;
			while (section != -1) {
				section = (byte) fileInput.read();
				arrayData.add(section);
			}
			fileData = convertToArray(arrayData);
			fileInput.close();
		} catch (Exception e) {
			System.out.println("Invalid file input, Exiting Program");
			System.exit(0);
		}
		System.out.println();
		scanner.close();
		return fileData;
	}
	
	/* ------------------------------------------
	 * 				Auxillary Methods
	 * ------------------------------------------*/
	
	
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
