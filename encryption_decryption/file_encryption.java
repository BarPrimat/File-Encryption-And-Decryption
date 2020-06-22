package encryption_decryption;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Properties;


public class  file_encryption extends FileProperties {
    public file_encryption(Properties properties,Path pathToPropertiesFile) {
        super(properties, pathToPropertiesFile);
    }

    private int sizeOfByteFile = 1024;

    public void encrypt(Path keyStorePath, String keyStorePassword, String alias, String keyPass, String crt, Path pathToPlainFile) throws IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, SignatureException, UnrecoverableKeyException, BadPaddingException, IllegalBlockSizeException {
        KeyStore ks = this.getKeyStore(keyStorePath, keyStorePassword);
        // Create IV with SecureRandom to generate pseudo random
        IvParameterSpec iv = IvCreator(getProperty("prndMethod"), Integer.parseInt(properties.getProperty("symmetricKeyIVSize")));
        SecretKey symmetricKey = KeyGenerator.getInstance(this.getProperty("symmetricAlgo")).generateKey();
        Cipher cipher = Cipher.getInstance(this.getTransformation());
        cipher.init(1, symmetricKey, iv);
        Path encryptedFilePath = pathToPlainFile.getParent().resolve("ciphertext.txt");

        // Encryption the file
        CipherOutputStream cipherFile = new CipherOutputStream(Files.newOutputStream(encryptedFilePath), cipher);
        InputStream fis = Files.newInputStream(pathToPlainFile);

        byte[] byteOfFile = new byte[sizeOfByteFile];
        int fisRead = fis.read(byteOfFile);
        while (fisRead != -1) {
            cipherFile.write(byteOfFile, 0, fisRead);
            fisRead = fis.read(byteOfFile);
        }
        if (fis != null) fis.close();
        if (cipherFile != null) cipherFile.close();
        // Now the file has encrypt

        // Encrypt the symmetric key with the PublicKey of the second user
        final byte[] signature = this.signEncryptedFile(this.calculateHashEncrypted(encryptedFilePath), this.getPrivateKey(ks, alias, keyPass));
        Cipher cip = Cipher.getInstance(getProperty("aSymmetricAlgo"));
        Certificate certificate = ks.getCertificate(crt);
        cip.init(1, certificate.getPublicKey());

        // Save the new data in the properties file
        this.saveProperties(signature, cip.doFinal(symmetricKey.getEncoded()), iv.getIV());
    }

    /**
     *  Save the new data in the properties file
     * @param signature
     * @param symmetricKeyEncryption
     * @param iv
     * @throws FileNotFoundException
     */
    private void saveProperties(byte[] signature, byte[] encryptedSymmetricKey, byte[] iv) throws FileNotFoundException, IOException {
        final Base64.Encoder base64Encoder = Base64.getEncoder();
        this.properties.put("symmetricKey", base64Encoder.encodeToString(encryptedSymmetricKey));
        this.properties.put("iv", base64Encoder.encodeToString(iv));
        this.properties.put("signature", base64Encoder.encodeToString(signature));
        this.properties.store(Files.newOutputStream(this.pathToPropertiesFile), "");
    }


    /**
     *  Create IV with SecureRandom to generate pseudo random
     * @param prndMethod
     * @param ivSize
     * @return IV
     * @throws NoSuchAlgorithmException
     */
    private static IvParameterSpec IvCreator(String prndMethod, int ivSize) throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance(prndMethod);
        byte[] ivBytes = new byte[ivSize];
        sr.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }

    /**
     *  sign the hash file with private key
     * @param encryptedFileHash
     * @param privateKey
     * @return
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws KeyStoreException
     */
    private byte[] signEncryptedFile(byte[] encryptedFileHash, PrivateKey privateKey) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, KeyStoreException {
        if (privateKey == null) {
            throw new KeyStoreException("Private key not found");
        }
        Signature sig = Signature.getInstance(this.getProperty("signatureType"));
        sig.initSign(privateKey);
        sig.update(encryptedFileHash);
        return sig.sign();
    }
}
