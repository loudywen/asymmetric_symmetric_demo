package com.devon.demo;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@SpringBootApplication
public class AsymmetricSymmetricDemoApplication implements CommandLineRunner {

    private Cipher cipher;

    public static void main(String[] args) {
        SpringApplication.run(AsymmetricSymmetricDemoApplication.class, args);
    }


    @Override
    public void run(String... args) throws Exception {

        //generateKeyPair("another");
        //generatePCK1();
        // generateAESKey("symmetric");

        //asymmetricDemo();
        //symmetricDemo();

        //asymmetric_symmetric_combo_demo();
    }

    private void asymmetric_symmetric_combo_demo() throws IOException, GeneralSecurityException {
        String temp = "whatever man~~~~~~~~~~~~~~~~~~~`";
        Path symmetrickeyPath = Paths.get("/Users/diwenlao/IdeaProjects/asymmetric_symmetric_demo/symmetric.key");
        byte[] secretKeyInByte = Files.readAllBytes(symmetrickeyPath);
        byte[] encryptedContentBySymmetricKey = encryptUsingSymmetricKey(temp.getBytes(), secretKeyInByte);
        System.out.println("encrypted content by symmetric key: " + Base64.getEncoder().encodeToString(encryptedContentBySymmetricKey));
        //    System.out.println("encrypted content by symmetric key: " + new String(encryptedContentBySymmetricKey));


        // encrypt
        Path publicKeyPath = Paths.get("/Users/diwenlao/IdeaProjects/asymmetric_symmetric_demo/key_pair.pub");
        byte[] publicKeyInByte = Files.readAllBytes(publicKeyPath);
        byte[] encryptedSymmetric = encryptUsingAsymmetricPublicKey(secretKeyInByte, getPublicKey(publicKeyInByte));


        // decrypt
        Path privateKeyPath = Paths.get("/Users/diwenlao/IdeaProjects/asymmetric_symmetric_demo/key_pair.key");
        byte[] privateKeyInByte = Files.readAllBytes(privateKeyPath);
        byte[] decryptedSymmetricKeyInByte = decryptUsingAsymmetricPrivateKey(encryptedSymmetric, getPrivateKey(privateKeyInByte));
        byte[] decryptedContentBySymmetricKey = decryptUsingSymmetricKey(encryptedContentBySymmetricKey, decryptedSymmetricKeyInByte);
        System.out.println("decrypted content by symmetric key: " + new String(decryptedContentBySymmetricKey));
    }

    private void symmetricDemo() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String temp = "whatever haha";

        Path symmetrickeyPath = Paths.get("/Users/diwenlao/IdeaProjects/asymmetric_symmetric_demo/symmetric.key");
        byte[] secretKeyInByte = Files.readAllBytes(symmetrickeyPath);
        byte[] encryptyContent = encryptUsingSymmetricKey(temp.getBytes(), secretKeyInByte);
        System.out.println("encryptContent: " + new String(encryptyContent));

        byte[] decryptyContent = decryptUsingSymmetricKey(encryptyContent, secretKeyInByte);
        System.out.println("decryptContent: " + new String(decryptyContent));
    }

    private byte[] decryptUsingSymmetricKey(byte[] input, byte[] secretKeyInByte) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        SecretKey secKey_d = new SecretKeySpec(secretKeyInByte, "AES");

        Cipher cipher = Cipher.getInstance("AES");

        cipher.init(Cipher.DECRYPT_MODE, secKey_d);
        byte[] newData = cipher.doFinal(input);
        //  String temp = Base64.getEncoder().encodeToString(newData);
        // System.out.println("==== " + temp);
        return newData;
    }


    private byte[] encryptUsingSymmetricKey(byte[] input, byte[] secretKeyInByte) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKey secKey = new SecretKeySpec(secretKeyInByte, "AES");

        Cipher cipher = Cipher.getInstance("AES");

        cipher.init(Cipher.ENCRYPT_MODE, secKey);
        byte[] newData = cipher.doFinal(input);
        //  String temp = Base64.getEncoder().encodeToString(newData);
        // System.out.println("==== " + temp);
        return newData;
    }

    private void generateAESKey(String fileName) throws NoSuchAlgorithmException, IOException {
        //Generate Symmetric key
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        SecretKey key = generator.generateKey();
        byte[] symmetricKey = key.getEncoded();
        System.out.println(Base64.getEncoder().encodeToString(symmetricKey));
        Files.write(Paths.get(fileName + ".key"), symmetricKey);
    }


    private void asymmetricDemo() throws IOException, GeneralSecurityException {
        String toEncrypt = "who  are you?";

        // encrypt
        Path publicKeyPath = Paths.get("/Users/diwenlao/IdeaProjects/asymmetric_symmetric_demo/key_pair.pub");
        byte[] publicKeyInByte = Files.readAllBytes(publicKeyPath);
        byte[] encryptedContent = encryptUsingAsymmetricPublicKey(toEncrypt.getBytes(), getPublicKey(publicKeyInByte));

        System.out.println(new String(encryptedContent));

        // decrypt
        Path privateKeyPath = Paths.get("/Users/diwenlao/IdeaProjects/asymmetric_symmetric_demo/key_pair.key");
        byte[] privateKeyInByte = Files.readAllBytes(privateKeyPath);
        byte[] decryptedContent = decryptUsingAsymmetricPrivateKey(encryptedContent, getPrivateKey(privateKeyInByte));

        System.out.println();
        System.out.println(new String(decryptedContent));
    }

    public byte[] encryptUsingAsymmetricPublicKey(byte[] input, PublicKey key)
            throws IOException, GeneralSecurityException {
        this.cipher = Cipher.getInstance("RSA");
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedContent = this.cipher.doFinal(input);
        //System.out.println("encrypted" + encryptedContent);
        return encryptedContent;
    }

    public byte[] decryptUsingAsymmetricPrivateKey(byte[] input, PrivateKey key)
            throws IOException, GeneralSecurityException {
        this.cipher = Cipher.getInstance("RSA");
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedContent = this.cipher.doFinal(input);
        //System.out.println("decrypted" + decryptedContent);
        return decryptedContent;
    }

    private void generatePCK1(Key key) throws IOException {
        Base64.Encoder encoder = Base64.getEncoder();


        String outFile2 = "different_format";
        Writer out = new FileWriter(outFile2 + ".key");
        out.write("-----BEGIN RSA PRIVATE KEY-----\n");
        out.write(encoder.encodeToString(key.getEncoded()));
        out.write("\n-----END RSA PRIVATE KEY-----\n");
        out.close();
    }

    private void generateKeyPair(String fileName) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        //set size 1024 or 2048, prefer 2048
        keyPairGenerator.initialize(2048);
        // generate key pair
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        // private
        Key privateKey = keyPair.getPrivate();
        // public
        Key publicKey = keyPair.getPublic();


        Files.write(Paths.get(fileName + ".key"), privateKey.getEncoded());
        System.out.println("private: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));

        Files.write(Paths.get(fileName + ".pub"), publicKey.getEncoded());
        System.out.println("public: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        System.out.println("private key format: " + privateKey.getFormat());

        System.out.println("public key format: " + publicKey.getFormat());
    }


    public PrivateKey getPrivateKey(byte[] privateKeyFile) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyFile);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(ks);
    }

    public PublicKey getPublicKey(byte[] publicKeyFile) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyFile);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(ks);

    }

    private void test_1() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        byte[] input = "abc".getBytes();
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");

        generator.initialize(256, random);

        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();

        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + new String(cipherText));

        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + new String(plainText));
    }
}
