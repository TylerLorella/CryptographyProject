import java.math.BigInteger;
import java.util.Scanner;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		System.out.println("Enter the message to make some gross nasty boi shit");
		Scanner s = new Scanner(System.in);
		String encryptMeDaddy = s.nextLine();
		s.close();
		
		//Key of 0 (as bigint)
		KMACXOF256 kmac = new KMACXOF256(BigInteger.ZERO, encryptMeDaddy, 256, "");
		
		System.out.println(kmac.getData());

	}

}
