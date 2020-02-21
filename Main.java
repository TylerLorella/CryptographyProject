import java.math.BigInteger;
import java.util.Scanner;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		//System.out.println("Enter the message to make some gross nasty boi shit");
		//Scanner s = new Scanner(System.in);
		//String encryptMeDaddy = s.nextLine();
		byte[] encryptMeDaddy = {00, 01, 02, 03};
		String diveyString = "Email Signature";
		//s.close();
		
		//Key of 0 (as bigint)
		KMACXOF256 kmac = new KMACXOF256(BigInteger.TEN, encryptMeDaddy, 32, diveyString);
		
		System.out.println("Result: \n" + kmac.getData());

	}

}
