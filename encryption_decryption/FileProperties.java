package encryption_decryption;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.PrivateKey;
import java.security.KeyStore;
import java.nio.file.Path;
import java.util.Properties;

public class FileProperties {
    protected Properties properties;
    protected Path pathToPropertiesFile;

    public FileProperties(Properties properties, Path pathToPropertiesFile) {
        this.properties = properties;
        this.pathToPropertiesFile = pathToPropertiesFile;
    }

    protected String getProperty(String key) {
        return this.properties.getProperty(key);
    }


    protected PrivateKey getPrivateKey(KeyStore keyStore, String pairName, String password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        return (PrivateKey)keyStore.getKey(pairName, password.toCharArray());
    }

    protected KeyStore getKeyStore(Path keystoreFilePath, String keyStorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(this.getProperty("keyStoreType"), this.getProperty("keyStoreProvider"));
        keyStore.load(Files.newInputStream(keystoreFilePath), keyStorePassword.toCharArray());
        return keyStore;
    }

    protected String getTransformation() {
        String transformation = this.getProperty("symmetricAlgo") + "/" + this.getProperty("symmetricAlgoMode")+ "/" + this.getProperty("symmetricAlgoPadding");
        return transformation;
    }

    protected byte[] calculateHashEncrypted(Path encryptedFilePath) {
        InputStream fis = null;
        MessageDigest messaged = null;
        try {
            messaged = MessageDigest.getInstance(this.getProperty("hashType"), this.getProperty("hashProvider"));
            fis = Files.newInputStream(encryptedFilePath);
            byte[] fileBytes = new byte[1024];
            int readFile = fis.read(fileBytes);
            while (readFile != -1) {
                messaged.update(fileBytes, 0, readFile);
                readFile = fis.read(fileBytes);
            }
            if(fis != null) fis.close();
        } catch (IOException  | NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (messaged != null) {
            return messaged.digest();
        }
        return null;
    }
}