
public class EncryptInformation extends AESEncrypt {

		public static String plaintext;
		public static String ciphertext;
		public static String plaintextD;
		
	
	public static void main(String[] args) throws Exception {
		
		
		plaintext = "This is a test";
		System.out.println("----Input-----");
		System.out.println("Input Text: " + plaintext);

		System.out.println("----Encrypt-----");
		try {
			ciphertext = encrypt(plaintext);
			System.out.println("This is ciphertext: " + ciphertext);
			Thread.currentThread().getStackTrace();
		} catch (Exception e) {
			Thread.currentThread().getStackTrace();
			e.printStackTrace();
			System.out.println(e.getMessage());
		}	
	
		System.out.println("----Decrpyt-----");
		try{
		plaintextD = decrypt(ciphertext);
		System.out.println("This is ciphertext: " + plaintextD);
		} catch (Exception e) {
			Thread.currentThread().getStackTrace();
			e.printStackTrace();
			System.out.println(e.getMessage());
		}
		
		
		
	}
}
