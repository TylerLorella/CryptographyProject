import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Scanner;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		//System.out.println("Enter the message to make some gross nasty boi shit");
		//Scanner s = new Scanner(System.in);
		//String encryptMeDaddy = s.nextLine();
		//byte[] encryptMeDaddy = {00, 01, 02, 03};
		byte[] encryptMeDaddy = {00, 01, 00, 11};
		byte[] testKey = {0b0};
		String diveyString = "Email Signature";
		//s.close();
		
		//Key of 0 (as bigint)
		//KMACXOF256 kmac = new KMACXOF256(testKey, encryptMeDaddy, 1, diveyString);
		//System.out.println("Result: \n" + kmac.getStringData());

		
		System.out.println("Cryptography Project by Max England, and Tyler Lorella");
		System.out.println("Enter digit for mode of operation: \n"
				+ "1-Hash");
		Scanner scanner = new Scanner(System.in);
		int mode = scanner.nextInt();
		System.out.println("Enter digit for input method: \n"
				+ "1-File Input; 2-String Input");
		int inputMethod = scanner.nextInt();
		
		byte [] data = {0x01};
		
		if (inputMethod == 1) {
			System.out.print("Enter file path: ");
			String filePath = scanner.nextLine();
			try {
				ArrayList<Byte> arrayData = new ArrayList<Byte>();
				FileInputStream fileInput = new FileInputStream(filePath);
				byte section = 0b0;
				while (section != -1) {
					section = (byte) fileInput.read();
					arrayData.add(section);
				}
				data = convertToArray(arrayData);
				fileInput.close();
			} catch (Exception e) {
				System.out.println("Invalid file input");
				System.exit(0);
			}
		} else {
			System.out.print("Enter input");
			String stringInput = scanner.nextLine();
			data = stringInput.getBytes();
		}
		//System.out.println(input);
		
		//modes
		//1 -  Hash - 
		if (mode == 1) {
			System.out.println(hashKMAC(data));
		} else if (mode == 2) {
			System.out.print("Enter Key:");
			String key = scanner.nextLine();
			System.out.println(macKMAC(key.getBytes(), data));
		}
		
		
		scanner.close();
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
	
	
	
	private static byte[] convertToArray(ArrayList<Byte> input) {
		byte[] toReturn = new byte[input.size()];
		for (int index = 0; index < input.size(); index++) {
			toReturn[index] = input.get(index);
		}
		return toReturn;
	}

}
