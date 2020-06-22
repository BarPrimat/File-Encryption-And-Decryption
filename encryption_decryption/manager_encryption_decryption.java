package encryption_decryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Properties;


public class manager_encryption_decryption {
    private static Path pathOfPropertiesFile;
    private static String propertiesFileName = "./conf.properties";

    public static void main(String[] args){
        Properties propFile = new Properties();
        if(args.length != 7) {
            System.out.println("The input is not legal the input need only 7 paramerters and you put: " + args.length);
            return;
        }
        try{
            pathOfPropertiesFile = Paths.get("./conf.properties", "");
            FileInputStream fls = new FileInputStream(propertiesFileName);
            propFile.load(Files.newInputStream(pathOfPropertiesFile));
            Path keyStorePath = Paths.get("./", args[0]);
            Path filePath = Paths.get("./", args[5]);
            if (args[6].equals("e")) {
                new file_encryption(propFile, pathOfPropertiesFile).encrypt(keyStorePath, args[1], args[2], args[3], args[4], filePath);
                System.out.println("The File is encrypt");
            }
            else {
                if (!args[6].equals("d")) {
                    throw new Exception("Bad mode given.");
                }
                new file_decryption(propFile, pathOfPropertiesFile).decrypt(keyStorePath, args[1], args[2], args[3], args[4], filePath);
                System.out.println("The File is decrypt and ready to read");
            }
            fls.close();
        } catch (IOException | NoSuchAlgorithmException | CertificateException | NoSuchProviderException | KeyStoreException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException | SignatureException | UnrecoverableKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("ERROR!! " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}