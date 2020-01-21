package thresholdsalt;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static thresholdsalt.DualSalt.*;

public class ThresholdSaltTest {

    @Test
    public void testDivideScalar() {
        byte[] a = {8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] b = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] r = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        byte[] i = ThresholdSalt.invertScalar(b);
        byte[] d = ThresholdSalt.multiplyScalars(a, i);

        assertArrayEquals("Divide do not work 8/4!=2", r, d);
    }

    @Test
    public void testDivideScalarRand() {

        for (int i = 0; i < 256; i++) {
            byte[] a = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
            byte[] b = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
            byte[] m = ThresholdSalt.multiplyScalars(a, b);

            assertArrayEquals("m/a!=b", b, ThresholdSalt.multiplyScalars(m, ThresholdSalt.invertScalar(a)));
            assertArrayEquals("m/b!=a", a, ThresholdSalt.multiplyScalars(m, ThresholdSalt.invertScalar(b)));
        }
    }

    @Test
    public void testPlayWithScalarInversion() {
        final byte[] d0 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        final byte[] d1 = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        final byte[] d2 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] workBuffer = d0;

        long[] l = TweetNaclFast.L.clone();
        l[0] = 0xeb;

        for (int i = 252; i >= 0; --i) {
            workBuffer = ThresholdSalt.multiplyScalars(workBuffer, d2);
            if (((l[i >>> 3] >>> (i & 7)) & 1) == 1) {
                workBuffer = addScalars(workBuffer, d1);
            }
        }

        byte[] m = new byte[32];
        for (int i = 0; i < 32; i++) {
            m[i] = (byte) l[i];
        }

        assertArrayEquals("Do not add up to L-2", m, workBuffer);
    }

    @Test
    public void testDivideGroupElement() {
        byte[] multiplier = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        byte[] secretKey = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        byte[] publicKey = baseScalarMult(secretKey);

        byte[] timesMultiplier = ThresholdSalt.scalarMultiply(publicKey, multiplier);
        byte[] divider = ThresholdSalt.invertScalar(multiplier);
        byte[] result = ThresholdSalt.scalarMultiply(timesMultiplier, divider);

        assertTrue("Arrays are not the same", Arrays.equals(publicKey, result));
    }

    @Test
    public void testDivideMultipleGroupElement() {
        int numberOfParts = 4;
        byte[] parts = standardShares(numberOfParts);
        byte[] secretKey = ThresholdSalt.modL(TweetNaclFast.randombytes(32));

        for (byte index = 0; index < numberOfParts; index++) {
            byte[] secretInZero = ThresholdSalt.calculateScalarInZero(secretKey, parts, index);
            byte[] publicInZero1 = baseScalarMult(secretInZero);

            byte[] publicPart = baseScalarMult(secretKey);
            byte[] publicInZero2 = ThresholdSalt.calculateGroupElementInZero(publicPart, parts, index);

            assertArrayEquals("Fail to do the same trick in the group", publicInZero1, publicInZero2);
        }
    }

    private byte[] recombineShare(byte[][] splits, byte[] orgParts, byte[] parts) {
        byte[][] secretParts = new byte[parts.length][];
        for (byte i = 0; i < parts.length; i++) {
            secretParts[i] = ThresholdSalt.calculateScalarInZero(splits[getIndexArray(orgParts, parts[i])], parts, parts[i]);
        }
        return ThresholdSalt.addScalarArray(secretParts);
    }

    @Test
    public void testShamirSplitAndJoin2of3() {
        byte[] parts = standardShares(3);
        byte[] secretKey = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        byte[][] rand = new byte[1][];
        rand[0] = ThresholdSalt.modL(TweetNaclFast.randombytes(32));

        byte[][] secretKeys = ThresholdSalt.splitScalar(secretKey, rand, parts);

        assertArrayEquals("Fail to recombine shares [1, 2]", secretKey, recombineShare(secretKeys, parts, new byte[]{1, 2}));
        assertArrayEquals("Fail to recombine shares [1, 3]", secretKey, recombineShare(secretKeys, parts, new byte[]{1, 3}));
        assertArrayEquals("Fail to recombine shares [2, 3]", secretKey, recombineShare(secretKeys, parts, new byte[]{2, 3}));
        assertArrayEquals("Fail to recombine shares [1, 2, 3]", secretKey, recombineShare(secretKeys, parts, new byte[]{1, 2, 3}));
    }

    @Test
    public void testShamirSplitAndJoin3of4() {
        byte[] parts = standardShares(4);
        byte[] secretKey = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        byte[][] rand = new byte[2][];
        rand[0] = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        rand[1] = ThresholdSalt.modL(TweetNaclFast.randombytes(32));

        byte[][] secretKeys = ThresholdSalt.splitScalar(secretKey, rand, parts);

        assertArrayEquals("Fail to recombine shares [1, 2, 3]", secretKey, recombineShare(secretKeys, parts, new byte[]{1, 2, 3}));
        assertArrayEquals("Fail to recombine shares [1, 2, 4]", secretKey, recombineShare(secretKeys, parts, new byte[]{1, 2, 4}));
        assertArrayEquals("Fail to recombine shares [1, 3, 4]", secretKey, recombineShare(secretKeys, parts, new byte[]{1, 3, 4}));
        assertArrayEquals("Fail to recombine shares [2, 3, 4]", secretKey, recombineShare(secretKeys, parts, new byte[]{2, 3, 4}));
        assertArrayEquals("Fail to recombine shares [1, 2, 3, 4]", secretKey, recombineShare(secretKeys, parts, new byte[]{1, 2, 3, 4}));
    }

    private byte getIndexArray(byte[] array, byte value){
        for (byte i = 0; i < array.length; i++) {
            if (value == array[i]){
                return i;
            }
        }
        return -1;
    }

    private byte[] standardShares(int count){
        byte[] out = new byte[count];
        for (byte i = 1; i <= count; i++) {
            out[i-1] = i;
        }
        return out;
    }

    @Test
    public void testDistributedPublicKeyCalculation2of3() {
        byte[] secretKey = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        byte[] publicKey = baseScalarMult(secretKey);

        byte[][] rand = new byte[1][];
        rand[0] = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        byte[] parts = standardShares(3);
        byte[][] secretKeys = ThresholdSalt.splitScalar(secretKey, rand, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);

        assertArrayEquals("Fail to recombine public key [1, 2]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{1, 2}));
        assertArrayEquals("Fail to recombine public key [1, 3]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{1, 3}));
        assertArrayEquals("Fail to recombine public key [2, 3]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{2, 3}));
        assertArrayEquals("Fail to recombine public key [1, 2, 3]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{1, 2, 3}));
    }

    @Test
    public void testDistributedPublicKeyCalculation3f4() {
        byte[] secretKey = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        byte[] publicKey = baseScalarMult(secretKey);

        byte[][] rand = new byte[2][];
        rand[0] = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        rand[1] = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        byte[] parts = standardShares(4);
        byte[][] secretKeys = ThresholdSalt.splitScalar(secretKey, rand, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);

        assertArrayEquals("Fail to recombine public key [1, 2, 3]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{1, 2, 3}));
        assertArrayEquals("Fail to recombine public key [1, 2, 4]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{1, 2, 4}));
        assertArrayEquals("Fail to recombine public key [1, 3, 4]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{1, 3, 4}));
        assertArrayEquals("Fail to recombine public key [2, 3, 4]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{2, 3, 4}));
        assertArrayEquals("Fail to recombine public key [1, 2, 3, 4]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{1, 2, 3, 4}));
    }

    private byte[][] keyPartGeneration(byte[] secret , int order, byte[] parts) {
        byte[][] rand = new byte[order - 1][];
        for (int i = 0; i < order - 1; i++) {
            rand[i] = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        }

        return ThresholdSalt.splitScalar(secret, rand, parts);
    }

    private byte[][] keyPartGeneration(int order, byte[] parts) {
        return keyPartGeneration(ThresholdSalt.modL(TweetNaclFast.randombytes(32)), order, parts);
    }

    private byte[][] distributedKeyGeneration(int order, byte[] parts) {
        byte[][][] listOfShareParts = new byte[parts.length][parts.length][];
        for (int i = 0; i < parts.length; i++) {
            listOfShareParts[i] = keyPartGeneration(order, parts);
        }

        byte[][][] listOfDistributeShares = distributeShares(listOfShareParts);

        byte[][] secrets = new byte[parts.length][];
        for (int i = 0; i < listOfDistributeShares.length; i++) {
            secrets[i] = ThresholdSalt.addScalarArray(listOfDistributeShares[i]);
        }
        return secrets;
    }

    private byte[][][] distributeShares(byte[][][] listOfShareParts ){
        byte[][][] returnValue = new byte[listOfShareParts[0].length][listOfShareParts.length][];

        for (int i = 0; i < listOfShareParts[0].length; i++) {
            for (int j = 0; j < listOfShareParts.length; j++) {
                returnValue[i][j] = listOfShareParts[j][i];
            }
        }
        return returnValue;
    }


    private byte[] thresholdDecryptTest(byte[] cipherMessage, byte[][] secretKeys, byte[] orgParts, byte[] parts) {
        byte[] d1 = ThresholdSalt.thresholdDecrypt1(cipherMessage);

        byte[][] d2 = new byte[parts.length][];
        for (int i = 0; i < parts.length; i++) {
            byte[] secretKey =  secretKeys[getIndexArray(orgParts, parts[i])];
            d2[i] = ThresholdSalt.thresholdDecrypt2(d1, secretKey);
        }

        return ThresholdSalt.thresholdDecrypt3(d2, cipherMessage, parts);
    }

    private byte[] thresholdSignTest(byte[][] secretKeys, byte[][] publicKeys, byte[] publicKey, byte[] message, byte[] orgParts, byte[] parts){

        byte[] m1 = ThresholdSalt.thresholdSign1(message);

        byte[][] rands = new byte[parts.length][];
        byte[][] m2 = new byte[parts.length][];
        for (int i = 0; i < parts.length; i++) {
            rands[i] = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
            m2[i] = ThresholdSalt.thresholdSign2(m1, rands[i]);
        }

        byte[] m3 = ThresholdSalt.thresholdSign3(m1, m2, publicKey, parts);

        byte[][] m4 = new byte[parts.length][];
        for (int i = 0; i < parts.length; i++) {
            byte[] secretKey = secretKeys[getIndexArray(orgParts, parts[i])];
            m4[i] = ThresholdSalt.thresholdSign4(m3, rands[i], secretKey);
        }


        byte[][] trimmedPublicKeys = new byte[parts.length][];
        for (int i = 0; i < parts.length; i++) {
            trimmedPublicKeys[i] = publicKeys[getIndexArray(orgParts, parts[i])];
        }
        return ThresholdSalt.thresholdSign5(m2, m3, m4, trimmedPublicKeys, parts);
    }

    @Test
    public void testDistributedKeyGeneration2of3() {
        byte[] parts = standardShares(3);
        byte[][] secretKeys = distributedKeyGeneration(2, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);
        byte[] publicKey = recombinePublicKeys(publicKeys, parts, parts);

        assertArrayEquals("Fail to recombine public key [1, 2]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{1, 2}));
        assertArrayEquals("Fail to recombine public key [1, 3]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{1, 3}));
        assertArrayEquals("Fail to recombine public key [2, 3]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{2, 3}));
    }

    @Test
    public void testDistributedKeyGeneration3of4() {
        byte[] parts = standardShares(4);
        byte[][] secretKeys = distributedKeyGeneration(3, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);
        byte[] publicKey = recombinePublicKeys(publicKeys, parts, parts);

        assertArrayEquals("Fail to recombine public key [1, 2, 3]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{1, 2, 3}));
        assertArrayEquals("Fail to recombine public key [1, 2, 4]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{1, 2, 4}));
        assertArrayEquals("Fail to recombine public key [1, 3, 4]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{1, 3, 4}));
        assertArrayEquals("Fail to recombine public key [2, 3, 4]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{2, 3, 4}));
    }

    @Test
    public void testDistributedKeyGenerationOde2of3() {
        byte[] parts = new byte[] {2, 4, 7};
        byte[][] secretKeys = distributedKeyGeneration(2, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);
        byte[] publicKey = recombinePublicKeys(publicKeys, parts, parts);

        assertArrayEquals("Fail to recombine public key [2, 4]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{2, 4}));
        assertArrayEquals("Fail to recombine public key [2, 7]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{2, 7}));
        assertArrayEquals("Fail to recombine public key [4, 7]", publicKey, recombinePublicKeys(publicKeys, parts, new byte[]{4, 7}));
    }

    @Test
    public void testThresholdDecrypt2of3() {
        byte[] parts = standardShares(3);
        byte[][] secretKeys = distributedKeyGeneration(2, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);
        byte[] publicKey = recombinePublicKeys(publicKeys, parts, parts);
        byte[] message = TweetNaclFast.randombytes(20);

        byte[] cipherMessage = encrypt(message, publicKey, TweetNaclFast.randombytes(32));

        assertArrayEquals("Fail to decrypt [1, 2]", message, thresholdDecryptTest(cipherMessage, secretKeys, parts, new byte[]{1, 2}));
        assertArrayEquals("Fail to decrypt [1, 3]", message, thresholdDecryptTest(cipherMessage, secretKeys, parts, new byte[]{1, 3}));
        assertArrayEquals("Fail to decrypt [2, 3]", message, thresholdDecryptTest(cipherMessage, secretKeys, parts, new byte[]{2, 3}));
    }

    @Test
    public void testThresholdDecrypt3of4() {
        byte[] parts = standardShares(4);
        byte[][] secretKeys = distributedKeyGeneration(3, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);
        byte[] publicKey = recombinePublicKeys(publicKeys, parts, parts);
        byte[] message = TweetNaclFast.randombytes(20);

        byte[] cipherMessage = encrypt(message, publicKey, TweetNaclFast.randombytes(32));

        assertArrayEquals("Fail to decrypt [1, 2, 3]", message, thresholdDecryptTest(cipherMessage, secretKeys, parts, new byte[]{1, 2, 3}));
        assertArrayEquals("Fail to decrypt [1, 2, 4]", message, thresholdDecryptTest(cipherMessage, secretKeys, parts, new byte[]{1, 2, 4}));
        assertArrayEquals("Fail to decrypt [1, 3, 4]", message, thresholdDecryptTest(cipherMessage, secretKeys, parts, new byte[]{1, 3, 4}));
        assertArrayEquals("Fail to decrypt [2, 3, 4]", message, thresholdDecryptTest(cipherMessage, secretKeys, parts, new byte[]{2, 3, 4}));
    }

    @Test
    public void testThresholdDecryptOde2of3() {
        byte[] parts = new byte[] {2, 4, 7};
        byte[][] secretKeys = distributedKeyGeneration(2, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);
        byte[] publicKey = recombinePublicKeys(publicKeys, parts, parts);
        byte[] message = TweetNaclFast.randombytes(20);

        byte[] cipherMessage = encrypt(message, publicKey, TweetNaclFast.randombytes(32));

        assertArrayEquals("Fail to decrypt [2, 4]", message, thresholdDecryptTest(cipherMessage, secretKeys, parts, new byte[]{2, 4}));
        assertArrayEquals("Fail to decrypt [2, 7]", message, thresholdDecryptTest(cipherMessage, secretKeys, parts, new byte[]{2, 7}));
        assertArrayEquals("Fail to decrypt [4, 7]", message, thresholdDecryptTest(cipherMessage, secretKeys, parts, new byte[]{4, 7}));
    }

    @Test
    public void testThresholdSign2of3() {
        byte[] parts = standardShares(3);
        byte[][] secretKeys = distributedKeyGeneration(2, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);
        byte[] publicKey = recombinePublicKeys(publicKeys, parts, parts);
        byte[] message = TweetNaclFast.randombytes(20);

        assertTrue("Verified signature failed [1, 2]", signVerify(
                thresholdSignTest(secretKeys, publicKeys, publicKey, message, parts, new byte[] {1, 2}), publicKey));
        assertTrue("Verified signature failed [1, 3]", signVerify(
                thresholdSignTest(secretKeys, publicKeys, publicKey, message, parts, new byte[] {1, 3}), publicKey));
        assertTrue("Verified signature failed [2, 3]", signVerify(
                thresholdSignTest(secretKeys, publicKeys, publicKey, message, parts, new byte[] {2, 3}), publicKey));
    }

    private byte[][] calculatePublicKeys(byte[][] secretKeys) {
        byte[][] publicParts = new byte[secretKeys.length][];
        for (int i = 0; i < publicParts.length; i++) {
            byte[] publicPart = baseScalarMult(secretKeys[i]);
            byte[] random = TweetNaclFast.randombytes(32);
            byte[] randomGroupElement = baseScalarMult(random);

            byte[] hash = calculateHash(randomGroupElement, publicPart, publicPart);
            byte[] signature = calculateSignature(random, hash, secretKeys[i]);

            byte[] publicKeyPart = new byte[dualPublicKeyLength];
            System.arraycopy(randomGroupElement, 0, publicKeyPart, 0, groupElementLength);
            System.arraycopy(signature, 0, publicKeyPart, groupElementLength, scalarLength);
            System.arraycopy(publicPart, 0, publicKeyPart, signatureLength, publicKeyLength);
            publicParts[i] = publicKeyPart;
        }
        return publicParts;
    }

    @Test
    public void testThresholdSign3of4() {
        byte[] parts = standardShares(4);
        byte[][] secretKeys = distributedKeyGeneration(3, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);
        byte[] publicKey = recombinePublicKeys(publicKeys, parts, parts);
        byte[] message = TweetNaclFast.randombytes(20);

        assertTrue("Verified signature failed [1, 2, 3]", signVerify(
                thresholdSignTest(secretKeys, publicKeys, publicKey, message, parts, new byte[] {1, 2, 3}), publicKey));
        assertTrue("Verified signature failed [1, 2, 4]", signVerify(
                thresholdSignTest(secretKeys, publicKeys, publicKey, message, parts, new byte[] {1, 2, 4}), publicKey));
        assertTrue("Verified signature failed [1, 3, 4]", signVerify(
                thresholdSignTest(secretKeys, publicKeys, publicKey, message, parts, new byte[] {1, 3, 4}), publicKey));
        assertTrue("Verified signature failed [2, 3, 4]", signVerify(
                thresholdSignTest(secretKeys, publicKeys, publicKey, message, parts, new byte[] {2, 3, 4}), publicKey));
    }

    @Test
    public void testThresholdSignOde2of3() {
        byte[] parts = new byte[] {2, 4, 7};
        byte[][] secretKeys = distributedKeyGeneration(2, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);
        byte[] publicKey = recombinePublicKeys(publicKeys, parts, parts);
        byte[] message = TweetNaclFast.randombytes(20);

        assertTrue("Verified signature failed [2, 4]", signVerify(
                thresholdSignTest(secretKeys, publicKeys, publicKey, message, parts, new byte[] {2, 4}), publicKey));
        assertTrue("Verified signature failed [2, 7]", signVerify(
                thresholdSignTest(secretKeys, publicKeys, publicKey, message, parts, new byte[] {2, 7}), publicKey));
        assertTrue("Verified signature failed [4, 7]", signVerify(
                thresholdSignTest(secretKeys, publicKeys, publicKey, message, parts, new byte[] {4, 7}), publicKey));
    }

    private byte[][] distributedKeyRotation(byte[][] secretKeys, byte[] orgParts, byte[] parts, int order, byte[] newParts) {

        byte[][][] listOfShareParts = new byte[parts.length][newParts.length][];
        for (int i = 0; i < parts.length; i++) {
            byte[] aSecretKey = ThresholdSalt.calculateScalarInZero(secretKeys[getIndexArray(orgParts, parts[i])], parts, parts[i]);
            listOfShareParts[i] = keyPartGeneration(aSecretKey, order, newParts);
        }

        byte[][][] listOfDistributeShares = distributeShares(listOfShareParts);

        byte[][] newSecretKeys = new byte[listOfDistributeShares.length][];
        for (int i = 0; i < listOfDistributeShares.length; i++) {
            newSecretKeys[i] = ThresholdSalt.addScalarArray(listOfDistributeShares[i]);
        }
        return newSecretKeys;
    }

    @Test
    public void testDistributedKeyRotation2of3to3of4() {
        byte[] parts = standardShares(3);
        byte[][] secretKeys = distributedKeyGeneration(2, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);
        byte[] publicKey = recombinePublicKeys(publicKeys, parts, parts);

        byte[] newParts = standardShares(4);
        byte[][] newSecretKeys = distributedKeyRotation(secretKeys, parts, parts, 3, newParts);
        byte[][] newPublicKeys = calculatePublicKeys(newSecretKeys);

        assertArrayEquals("Fail to recombine public key [1, 2, 3]", publicKey, recombinePublicKeys(newPublicKeys, newParts, new byte[]{1, 2, 3}));
        assertArrayEquals("Fail to recombine public key [1, 2, 4]", publicKey, recombinePublicKeys(newPublicKeys, newParts, new byte[]{1, 2, 4}));
        assertArrayEquals("Fail to recombine public key [1, 3, 4]", publicKey, recombinePublicKeys(newPublicKeys, newParts, new byte[]{1, 3, 4}));
        assertArrayEquals("Fail to recombine public key [2, 3, 4]", publicKey, recombinePublicKeys(newPublicKeys, newParts, new byte[]{2, 3, 4}));
    }

    @Test
    public void testDistributedKeyRotation3of4to2of3() {
        byte[] parts = standardShares(4);
        byte[][] secretKeys = distributedKeyGeneration(3, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);
        byte[] publicKey = recombinePublicKeys(publicKeys, parts, parts);

        byte[] newParts = standardShares(3);
        byte[][] newSecretKeys = distributedKeyRotation(secretKeys, parts, parts, 2, newParts);
        byte[][] newPublicKeys = calculatePublicKeys(newSecretKeys);

        assertArrayEquals("Fail to recombine public key [1, 2]", publicKey, recombinePublicKeys(newPublicKeys, newParts, new byte[]{1, 2}));
        assertArrayEquals("Fail to recombine public key [1, 3]", publicKey, recombinePublicKeys(newPublicKeys, newParts, new byte[]{1, 3}));
        assertArrayEquals("Fail to recombine public key [2, 3]", publicKey, recombinePublicKeys(newPublicKeys, newParts, new byte[]{2, 3}));
    }

    @Test
    public void testDistributedKeyRotation3of4to2of3Ode() {
        byte[] parts = standardShares(4);
        byte[][] secretKeys = distributedKeyGeneration(3, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);
        byte[] publicKey = recombinePublicKeys(publicKeys, parts, parts);

        byte[] newParts = standardShares(3);
        byte[][] newSecretKeys = distributedKeyRotation(secretKeys, parts, new byte[]{1, 2, 4}, 2, newParts);
        byte[][] newPublicKeys = calculatePublicKeys(newSecretKeys);

        assertArrayEquals("Fail to recombine public key [1, 2]", publicKey, recombinePublicKeys(newPublicKeys, newParts, new byte[]{1, 2}));
        assertArrayEquals("Fail to recombine public key [1, 3]", publicKey, recombinePublicKeys(newPublicKeys, newParts, new byte[]{1, 3}));
        assertArrayEquals("Fail to recombine public key [2, 3]", publicKey, recombinePublicKeys(newPublicKeys, newParts, new byte[]{2, 3}));
    }

    private byte[] recombinePublicKeys(byte[][] publicParts, byte[] orgParts, byte[] parts) {
        byte[][] groupElements = new byte[orgParts.length][];
        for (byte i = 0; i < orgParts.length; i++) {
            if (publicParts[i].length != dualPublicKeyLength)
                throw new IllegalArgumentException("One public key has the wrong length");
            groupElements[i] = Arrays.copyOfRange(publicParts[i], signatureLength, dualPublicKeyLength);
            if (!signVerify(publicParts[i], groupElements[i]))
                throw new IllegalArgumentException("publicKeyPartA do not validate correctly");
        }
        return recombineGroupElements(groupElements, orgParts, parts);
    }

    private byte[] recombineGroupElements(byte[][] groupElements, byte[] orgParts, byte[] parts) {
        byte[][] newGroupElements = new byte[parts.length][];
        for (byte i = 0; i < parts.length; i++) {
            newGroupElements[i] = ThresholdSalt.calculateGroupElementInZero(groupElements[getIndexArray(orgParts, parts[i])], parts, parts[i]);
        }
        return ThresholdSalt.addGroupElementArray(newGroupElements);
    }

    public static byte[] calculateGroupElement(byte[] groupElements, byte[] players, byte player, byte xValue){
        byte[] omega = lagrangeInterpolation(players, player, xValue);
        byte[] numerator = ThresholdSalt.byteToScalar((byte) Math.abs(omega[0]));
        byte[] denominator = ThresholdSalt.byteToScalar((byte) Math.abs(omega[1]));

        byte[] multiplier =ThresholdSalt.multiplyScalars(ThresholdSalt.invertScalar(denominator), numerator);
        byte[] out = ThresholdSalt.scalarMultiply(groupElements, multiplier);

        if ( omega[0]<0 ^ omega[1]<0 ){
            out[31] = (byte) (out[31] ^ 0x80);
        }

        return out;
    }

    public static byte[] lagrangeInterpolation(byte[] players, byte player, byte xValue) {
        byte[] result = {1, 1}; // [numerator, denominator]

        for (byte currentPlayer : players) {
            if (currentPlayer != player) {
                result[0] *= currentPlayer - xValue;
                result[1] *= currentPlayer - player;
            }
        }

        return result;
    }

    private byte[] recombinePublicKeysForX(byte[][] publicParts, byte[] orgParts, byte[] parts, byte xValue) {
        byte[][] groupElements = new byte[orgParts.length][];
        for (byte i = 0; i < orgParts.length; i++) {
            if (publicParts[i].length != dualPublicKeyLength)
                throw new IllegalArgumentException("One public key has the wrong length");
            groupElements[i] = Arrays.copyOfRange(publicParts[i], signatureLength, dualPublicKeyLength);
            if (!signVerify(publicParts[i], groupElements[i]))
                throw new IllegalArgumentException("publicKeyPartA do not validate correctly");
        }
        return recombineGroupElementsForX(groupElements, orgParts, parts, xValue);
    }

    private byte[] recombineGroupElementsForX(byte[][] groupElements, byte[] orgParts, byte[] parts, byte xValue) {
        byte[][] newGroupElements = new byte[parts.length][];
        for (byte i = 0; i < parts.length; i++) {
            newGroupElements[i] = calculateGroupElement(groupElements[getIndexArray(orgParts, parts[i])], parts, parts[i], xValue);
        }
        return ThresholdSalt.addGroupElementArray(newGroupElements);
    }


    // ToDo Create more testes
    @Test
    public void testCheckForBadPublicKey() {
        byte[] parts = standardShares(4);
        byte[] secretKey = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        byte[] publicPart = baseScalarMult(secretKey);

        byte[][] rand = new byte[2][];
        rand[0] = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        rand[1] = ThresholdSalt.modL(TweetNaclFast.randombytes(32));
        byte[][] secretKeys = ThresholdSalt.splitScalar(secretKey, rand, parts);
        byte[][] publicKeys = calculatePublicKeys(secretKeys);

        assertArrayEquals("Fail to recombine shares [1, 2, 3]", publicPart, recombinePublicKeys(publicKeys, parts, new byte[]{1, 2, 3}));
        assertArrayEquals("Fail to recombine shares [1, 2, 4]", publicPart, recombinePublicKeys(publicKeys, parts, new byte[]{1, 2, 4}));
        assertArrayEquals("Fail to recombine shares [1, 3, 4]", publicPart, recombinePublicKeys(publicKeys, parts, new byte[]{1, 3, 4}));
        assertArrayEquals("Fail to recombine shares [2, 3, 4]", publicPart, recombinePublicKeys(publicKeys, parts, new byte[]{2, 3, 4}));
        assertArrayEquals("Fail to recombine shares [1, 2, 3, 4]", publicPart, recombinePublicKeys(publicKeys, parts, new byte[]{1, 2, 3, 4}));

        assertArrayEquals("Fail to create 1 from [2, 3, 4]", Arrays.copyOfRange(publicKeys[0], signatureLength, dualPublicKeyLength),
                recombinePublicKeysForX(publicKeys, parts, new byte[]{2, 3, 4}, (byte)1));
        assertArrayEquals("Fail to create 2 from [1, 3, 4]", Arrays.copyOfRange(publicKeys[1], signatureLength, dualPublicKeyLength),
                recombinePublicKeysForX(publicKeys, parts, new byte[]{1, 3, 4}, (byte)2));
        assertArrayEquals("Fail to create 3 from [1, 2, 4]", Arrays.copyOfRange(publicKeys[2], signatureLength, dualPublicKeyLength),
                recombinePublicKeysForX(publicKeys, parts, new byte[]{1, 2, 4}, (byte)3));
        assertArrayEquals("Fail to create 4 from [1, 2, 3]", Arrays.copyOfRange(publicKeys[3], signatureLength, dualPublicKeyLength),
                recombinePublicKeysForX(publicKeys, parts, new byte[]{1, 2, 3}, (byte)4));
    }
}
