package thresholdsalt;

import org.junit.Test;

import java.io.File;
import java.net.URL;
import java.util.Arrays;
import java.util.Scanner;

import static org.junit.Assert.*;
import static thresholdsalt.DualSalt.*;

public class DualSaltTestVectorTest {
    @Test
    public void testEddsaTestVector() throws Exception {
        System.out.println("\nTest EdDSA test vector");

        String fileName = "sign.input";
        URL url = DualSaltTest.class.getResource(fileName);
        File file = new File(url.getPath());

        try (Scanner sc = new Scanner(file)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] items = line.split(":");
                byte[] dutSecretKey = TweetNaclFast.hexDecode(items[0]);
                byte[] dutPublicKey = TweetNaclFast.hexDecode(items[1]);
                byte[] dutMessage = TweetNaclFast.hexDecode(items[2]);
                byte[] dutSignature = TweetNaclFast.hexDecode(items[3]);

                byte[] secretKeySeed = Arrays.copyOfRange(dutSecretKey, 0, seedLength);
                byte[] secretKey = new byte[secretKeyLength];
                byte[] publicKey = new byte[publicKeyLength];
                createSingleKeyPair(publicKey, secretKey, secretKeySeed);
                assertArrayEquals("Public key do not match", dutPublicKey, publicKey);

                byte[] signature = signCreate(dutMessage, dutSecretKey);
                assertTrue("Signature do not verify correctly", signVerify(signature, publicKey));
                assertArrayEquals("Signature do not match", dutSignature, signature);
            }
        }

        System.out.println("Test succeeded");
    }

    @Test
    public void testSignDualTestVector() throws Exception {
        System.out.println("\nTest sing dual test vector");

        String fileName = "signDual.input";
        URL url = DualSaltTest.class.getResource(fileName);
        File file = new File(url.getPath());

        try (Scanner sc = new Scanner(file)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] items = line.split(":");
                byte[] dutKeySeedA = TweetNaclFast.hexDecode(items[0]);
                byte[] dutPublicPartA = TweetNaclFast.hexDecode(items[1]);
                byte[] dutRandA = TweetNaclFast.hexDecode(items[2]);
                byte[] dutKeySeedB = TweetNaclFast.hexDecode(items[3]);
                byte[] dutPublicPartB = TweetNaclFast.hexDecode(items[4]);
                byte[] dutRandB = TweetNaclFast.hexDecode(items[5]);
                byte[] dutVirtualPublicKey = TweetNaclFast.hexDecode(items[6]);
                byte[] dutMessage = TweetNaclFast.hexDecode(items[7]);
                byte[] dutSignature  = TweetNaclFast.hexDecode(items[8]);

                byte[] secretKeyA = new byte[dualSecretKeyLength];
                byte[] publicKeyA = new byte[dualPublicKeyLength];
                byte[] secretKeyB = new byte[dualSecretKeyLength];
                byte[] publicKeyB = new byte[dualPublicKeyLength];

                createDualKeyPair(publicKeyA, secretKeyA, dutKeySeedA);
                assertArrayEquals("Public key A do not match", dutPublicPartA, publicKeyA);

                createDualKeyPair(publicKeyB, secretKeyB, dutKeySeedB);
                assertArrayEquals("Public key B do not match", dutPublicPartB, publicKeyB);

                byte[] virtualPublicKey = addPublicKeyParts(publicKeyA, publicKeyB);
                assertArrayEquals("Virtual public key do not match", dutVirtualPublicKey, virtualPublicKey);

                byte[] m1 = signCreateDual1(dutMessage, secretKeyA, virtualPublicKey, dutRandA);
                byte[] m2 = signCreateDual2(m1, secretKeyB, dutRandB);
                byte[] signature = signCreateDual3(m1, m2, secretKeyA, dutRandA);

                assertTrue("Signature do not verify correctly", signVerify(signature, virtualPublicKey));
                assertArrayEquals("Signature do not match", dutSignature, signature);
            }
        }

        System.out.println("Test succeeded");
    }

    @Test
    public void testDecryptTestVector() throws Exception {
        System.out.println("\nTest decrypt test vector");

        String fileName = "decrypt.input";
        URL url = DualSaltTest.class.getResource(fileName);
        File file = new File(url.getPath());

        try (Scanner sc = new Scanner(file)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] items = line.split(":");
                byte[] dutKeySeed = TweetNaclFast.hexDecode(items[0]);
                byte[] dutPublicKey = TweetNaclFast.hexDecode(items[1]);
                byte[] dutTempKeySeed = TweetNaclFast.hexDecode(items[2]);
                byte[] dutMessage = TweetNaclFast.hexDecode(items[3]);
                byte[] dutChipperText = TweetNaclFast.hexDecode(items[4]);

                byte[] secretKey = new byte[secretKeyLength];
                byte[] publicKey = new byte[publicKeyLength];
                createSingleKeyPair(publicKey, secretKey, dutKeySeed);
                assertArrayEquals("Public key do not match", dutPublicKey, publicKey);

                byte[] chipperText = encrypt(dutMessage, publicKey, dutTempKeySeed);
                byte[] message = decrypt(chipperText, secretKey);

                assertArrayEquals("Did not encrypt correctly", chipperText, dutChipperText);

                assertArrayEquals("Did not decrypt correctly", message, dutMessage);
            }
        }

        System.out.println("Test succeeded");
    }

    @Test
    public void testDecryptDualTestVector() throws Exception {
        System.out.println("\nTest decrypt dual test vector");

        String fileName = "decryptDual.input";
        URL url = DualSaltTest.class.getResource(fileName);
        File file = new File(url.getPath());

        try (Scanner sc = new Scanner(file)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] items = line.split(":");
                byte[] dutKeySeedA = TweetNaclFast.hexDecode(items[0]);
                byte[] dutPublicPartA = TweetNaclFast.hexDecode(items[1]);
                byte[] dutKeySeedB = TweetNaclFast.hexDecode(items[2]);
                byte[] dutPublicPartB = TweetNaclFast.hexDecode(items[3]);
                byte[] dutVirtualPublicKey = TweetNaclFast.hexDecode(items[4]);
                byte[] dutTempKeySeed = TweetNaclFast.hexDecode(items[5]);
                byte[] dutMessage = TweetNaclFast.hexDecode(items[6]);
                byte[] dutChipperText = TweetNaclFast.hexDecode(items[7]);

                byte[] secretKeyA = new byte[dualSecretKeyLength];
                byte[] publicKeyA = new byte[dualPublicKeyLength];
                byte[] secretKeyB = new byte[dualSecretKeyLength];
                byte[] publicKeyB = new byte[dualPublicKeyLength];

                createDualKeyPair(publicKeyA, secretKeyA, dutKeySeedA);
                assertArrayEquals("Public key A do not match", dutPublicPartA, publicKeyA);

                createDualKeyPair(publicKeyB, secretKeyB, dutKeySeedB);
                assertArrayEquals("Public key B do not match", dutPublicPartB, publicKeyB);

                byte[] virtualPublicKey = addPublicKeyParts(publicKeyA, publicKeyB);
                assertArrayEquals("Virtual public key do not match", dutVirtualPublicKey, virtualPublicKey);

                byte[] chipperText = encrypt(dutMessage, virtualPublicKey, dutTempKeySeed);
                byte[] d1 = decryptDual1(chipperText, secretKeyA);
                byte[] message = decryptDual2(d1, chipperText, secretKeyB);

                assertArrayEquals("Did not encrypt correctly", chipperText, dutChipperText);

                assertArrayEquals("Did not decrypt correctly", message, dutMessage);
            }
        }

        System.out.println("Test succeeded");
    }

    @Test
    public void testKeyRotateTestVector() throws Exception {
        System.out.println("\nTest key rotate test vector");

        String fileName = "keyRotate.input";
        URL url = DualSaltTest.class.getResource(fileName);
        File file = new File(url.getPath());

        try (Scanner sc = new Scanner(file)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] items = line.split(":");
                byte[] dutKeySeedA = TweetNaclFast.hexDecode(items[0]);
                byte[] dutPublicPartA = TweetNaclFast.hexDecode(items[1]);
                byte[] dutKeySeedB = TweetNaclFast.hexDecode(items[2]);
                byte[] dutPublicPartB = TweetNaclFast.hexDecode(items[3]);
                byte[] dutVirtualPublicKey = TweetNaclFast.hexDecode(items[4]);
                byte[] dutRotateRandom = TweetNaclFast.hexDecode(items[5]);
                byte[] dutNewSecretKeyA = TweetNaclFast.hexDecode(items[6]);
                byte[] dutNewSecretKeyB  = TweetNaclFast.hexDecode(items[7]);

                byte[] secretKeyA = new byte[dualSecretKeyLength];
                byte[] publicKeyA = new byte[dualPublicKeyLength];
                byte[] secretKeyB = new byte[dualSecretKeyLength];
                byte[] publicKeyB = new byte[dualPublicKeyLength];

                createDualKeyPair(publicKeyA, secretKeyA, dutKeySeedA);
                assertArrayEquals("Public key A do not match", dutPublicPartA, publicKeyA);

                createDualKeyPair(publicKeyB, secretKeyB, dutKeySeedB);
                assertArrayEquals("Public key B do not match", dutPublicPartB, publicKeyB);

                byte[] virtualPublicKey = addPublicKeyParts(publicKeyA, publicKeyB);
                assertArrayEquals("Virtual public key do not match", dutVirtualPublicKey, virtualPublicKey);

                byte[] newSecretKeyA = rotateKey(secretKeyA, dutRotateRandom, true);
                byte[] newSecretKeyB = rotateKey(secretKeyB, dutRotateRandom, false);

                assertArrayEquals("Secret Key A was not updated correctly", newSecretKeyA, dutNewSecretKeyA);
                assertArrayEquals("Secret Key B was not updated correctly", newSecretKeyB, dutNewSecretKeyB);
            }
        }

        System.out.println("Test succeeded");
    }
}