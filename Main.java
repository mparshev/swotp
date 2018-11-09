package my.swift;

import com.google.android.apps.authenticator.Base32String;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Scanner;
import java.util.prefs.Preferences;

public class Main {

    static final int DIGITS = 8;
    static final String HMACSHA = "HmacSHA256";
    static final String PBKDF2WithHmacSHA256 = "PBKDF2WithHmacSHA256";

    private static final String SALT = "SWIFT Alliance Access 7.2";
    private static final String CIPHER = "AES/CBC/PKCS5Padding";

    static final int TIMESTEP = 30;

    private static String getHOTP(String secret, long counter) {
        ByteBuffer bb = ByteBuffer.allocate(DIGITS);
        bb.putLong(counter);

        int div = 1;
        for(int i = DIGITS; i > 0; i--)
            div *= 10;

        try {
            byte[] s = Base32String.decode(secret);

            Mac mac = Mac.getInstance(HMACSHA);
            mac.init(new SecretKeySpec(s,HMACSHA));

            // Do the hashing
            byte[] digest = mac.doFinal(bb.array());

            // Truncate
            int binary;
            int off = digest[digest.length - 1] & 0xf;
            binary = (digest[off] & 0x7f) << 0x18;
            binary |= (digest[off + 1] & 0xff) << 0x10;
            binary |= (digest[off + 2] & 0xff) << 0x08;
            binary |= (digest[off + 3] & 0xff);
            binary = binary % div;

            // Zero pad
            String hotp = Integer.toString(binary);
            while (hotp.length() != DIGITS)
                hotp = "0" + hotp;

            return hotp;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Base32String.DecodingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return "";
    }


    private static SecretKey getSecretKey(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2WithHmacSHA256);
        KeySpec spec = new PBEKeySpec(password, SALT.getBytes(), 1000, 128);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private static void encryptSecret(String secret, char[] password) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(password));
            AlgorithmParameters params = cipher.getParameters();
            byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
            byte[] ct = cipher.doFinal(secret.getBytes("UTF-8"));
            Preferences prefs = Preferences.userNodeForPackage(Main.class);
            prefs.putByteArray("iv",iv);
            prefs.putByteArray("ct",ct);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String decryptSecret(char[] password) {
        try {
            Preferences prefs = Preferences.userNodeForPackage(Main.class);
            byte[] iv = prefs.getByteArray("iv", null);
            byte[] ct = prefs.getByteArray("ct", null);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(password), new IvParameterSpec(iv));
            return new String(cipher.doFinal(ct), "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Can\'t get secret");
        }
    }

    private static String readString(String prompt) {
        Scanner sc = new Scanner(System.in);
        System.out.print(prompt);
        return sc.nextLine();
    }

    private static char[] readPassword(String prompt) {
        Console console = System.console();
        if( console == null ) {
            return readString(prompt).toCharArray();
        } else {
            return console.readPassword(prompt);
        }
    }

    public static void main(String[] args) throws InterruptedException, IOException {

        //String secret = "VCDK 3M2A ORVX UQQA XFEB OQCL HWUY AHAJ Y3RD HD7Q OXXE CKRI 2MGA";

        if(args.length > 0 && "/init".equalsIgnoreCase(args[0])) {
            String secret = readString("Enter your secret:");
            char[] password = readPassword("Password:");
            encryptSecret(secret,password);
        }

        char[] password = readPassword("Password:");
        String secret = decryptSecret(password);
        //System.out.println(secret);
        long counter0 = 0L;
        while(System.in.available()==0) {
            long counter = System.currentTimeMillis() / TIMESTEP / 1000;
            if(counter!=counter0) {
                System.out.println("" + getHOTP(secret, counter));
            }
            counter0 = counter;
            //Thread.sleep( (counter + 1) * TIMESTEP * 1000 - System.currentTimeMillis() );
        }
    }
}
