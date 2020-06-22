package encryption_decryption;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Properties;

public class file_decryption extends FileProperties{
    public file_decryption(final Properties properties, final Path propertiesFilePath) {
        super(properties, propertiesFilePath);
    }

    private int sizeOfByteFile = 1024;

    public void decrypt(Path keyStorePath, String keyStorePassword, String alias, String keyPass, String crt, Path pathToEncryptedFile) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnrecoverableKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, SignatureException {
        KeyStore ks = this.getKeyStore(keyStorePath, keyStorePassword);

        // Read the value from property file
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encryptedAes = decoder.decode(getProperty("symmetricKey"));
        byte[] iv = decoder.decode(getProperty("iv"));
        byte[] signature = decoder.decode(getProperty("signature"));
        // Decrypted the symmetric key from the properties file using private key and symmetric algorithm that given
        byte[] aesKey = decryptSymmetricKey(getProperty("aSymmetricAlgo"), this.getPrivateKey(ks, alias, keyPass), encryptedAes);
        final Path decryptedFilePath = pathToEncryptedFile.getParent().resolve("decrypted.txt");
        //
        this.decryptFile(aesKey, iv, pathToEncryptedFile, decryptedFilePath);
        // Verify the given signature from the properties file
        if (!this.verifySignature(this.calculateHashEncrypted(pathToEncryptedFile), signature, ks, crt)) {
            OutputStream fis = Files.newOutputStream(decryptedFilePath);
            fis.write("The signature was not verified".getBytes());
            System.err.println("There is some problem with verified");
            if (fis != null) fis.close();
        }
    }

    /**
     *  Verify the given signature from the properties file
     * @param hash
     * @param signature
     * @param keyStore
     * @param crtAlias
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws KeyStoreException
     * @throws SignatureException
     */
    private boolean verifySignature(final byte[] hash, final byte[] signature, final KeyStore keyStore, final String crtAlias) throws NoSuchAlgorithmException, InvalidKeyException, KeyStoreException, SignatureException {
        final Signature sig = Signature.getInstance(this.getProperty("signatureType"));
        sig.initVerify(keyStore.getCertificate(crtAlias).getPublicKey());
        sig.update(hash);
        return sig.verify(signature);
    }

    /**
     * Decrypt the file with the iv and the symmetric key
     * @param aesKey
     * @param iv
     * @param encrypedFilePath
     * @param decrypedFilePath
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IOException
     */
    private void decryptFile(final byte[] aesKey, final byte[] iv, final Path encrypedFilePath, final Path decrypedFilePath) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        final SecretKeySpec sks = new SecretKeySpec(aesKey, this.getProperty("symmetricAlgo"));
        final IvParameterSpec ivParam = new IvParameterSpec(iv);
        final Cipher cipher = Cipher.getInstance(this.getTransformation());
        cipher.init(2, sks, ivParam);
        CipherInputStream cis = new CipherInputStream(Files.newInputStream(encrypedFilePath), cipher);
        OutputStream outSFile = Files.newOutputStream(decrypedFilePath);
        byte[] byteOfFile = new byte[sizeOfByteFile];
        int fisRead = cis.read(byteOfFile);
        while (fisRead != -1) {
            outSFile.write(byteOfFile, 0, fisRead);
            fisRead = cis.read(byteOfFile);
        }
        if (outSFile != null) outSFile.close();

    }

    /**
     * Decrypted the symmetric key from the properties file using private key and symmetric algorithm that given
     * @param aSymmerticAlgo
     * @param privateKey
     * @param encryptedAes
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws KeyStoreException
     */
    private byte[] decryptSymmetricKey(final String aSymmerticAlgo, final PrivateKey privateKey, final byte[] encryptedAes) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, KeyStoreException {
        if (privateKey == null) {
            throw new KeyStoreException("Private key not found");
        }
        final Cipher cipher = Cipher.getInstance(aSymmerticAlgo);
        cipher.init(2, privateKey);
        return cipher.doFinal(encryptedAes);
    }
}
