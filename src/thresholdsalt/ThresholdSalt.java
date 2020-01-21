package thresholdsalt;

import java.util.Arrays;
import static thresholdsalt.DualSalt.*;

public class ThresholdSalt {

    public static final byte[] scalar0 = new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    private static final byte[] scalar1 = new byte[]{0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    public static byte[] multiplyScalars(byte[] a, byte[]b){
        byte[] result = new byte[32];
        int i, j;
        long[] x = new long[64];
        for (i = 0; i < 64; i++)
            x[i] = 0;
        for (i = 0; i < 32; i++)
            x[i] = 0;
        for (i = 0; i < 32; i++)
            for (j = 0; j < 32; j++)
                x[i + j] += (a[i] & 0xff) * (long) (b[j] & 0xff);
        TweetNaclFast.modL(result, 0, x);
        return result;
    }

    public static byte[] invertScalar(byte[] a) {
        // l = L - 2
        final long l[] = { 0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c,
                0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };

        byte[] workBuffer = scalar1;

        for(int i = 252; i >= 0; --i) {
            workBuffer = multiplyScalars(workBuffer, workBuffer);
            if (((l[i >>> 3] >>> (i & 7)) & 1) == 1) {
                workBuffer = multiplyScalars(workBuffer, a);
            }
        }

        return workBuffer;
    }

    public static byte[] modL(byte[] in) {
        long[] temp = new long[64];

        for (int i = 0; i < in.length; i++) {
            temp[i] = in[i];
        }

        byte[] out = new byte[32];
        TweetNaclFast.modL(out, 0 , temp);

        return out;
    }

    public static byte[] lagrangeInterpolationInZero(byte[] players, byte player) {
        byte[] result = {1, 1}; // [numerator, denominator]

        for (byte currentPlayer : players) {
            if (currentPlayer != player) {
                result[0] *= currentPlayer;
                result[1] *= currentPlayer - player;
            }
        }

        return result;
    }

    public static byte[] calculateScalarInZero(byte[] scalar, byte[] players, byte player){
        byte[] omega = lagrangeInterpolationInZero(players, player);
        byte numerator = omega[0];
        byte denominator = omega[1];

        byte[] out = multiplyScalars(scalar, byteToScalar((byte) Math.abs(numerator)));
        out = multiplyScalars(out, invertScalar(byteToScalar((byte) Math.abs(denominator))));

        if ( numerator<0 ^ denominator<0 ){
            out = subtractScalars(scalar0, out);
        }

        return out;
    }

    public static byte[][] splitScalar(byte[] scalar, byte[][] coefficients, byte[] players) {

        byte[][] shares = new byte[players.length][];

        for (byte index = 0; index < players.length; index++) {
            shares[index] = scalar0.clone();
            byte[] scalarPlayer = byteToScalar(players[index]);
            for (byte[] coefficient : coefficients) { // ToDo: Do not really mather but coefficients shall be reversed
                shares[index] = addScalars(shares[index], coefficient);
                shares[index] = multiplyScalars(shares[index], scalarPlayer);
            }

            shares[index] = addScalars(shares[index], scalar);
        }

        return shares;
    }

    public static byte[] byteToScalar(byte in){
        byte[] out = scalar0.clone();
        out[0] = in;
        return out;
    }

    public static byte[] addGroupElementArray(byte[][] groupEls){
        byte[] out = groupEls[0];
        for (int i = 1; i < groupEls.length; i++) {
            out = addGroupElements(out, groupEls[i]);
        }
        return out;
    }

    public static byte[] addScalarArray(byte[][] scalars) {
        byte[] out = scalars[0];
        for (int i = 1; i < scalars.length; i++) {
            out = addScalars(out, scalars[i]);
        }
        return out;
    }

    private static byte[] recombineGroupElements(byte[][] groupElements, byte[] parts) {
        // ToDo Optimize, The inversion in calculateGroupElementInZero() only need to be done once. ~inv(part.length!)
        byte[][] newGroupElements = new byte[parts.length][];
        for (byte i = 0; i < parts.length; i++) {
            newGroupElements[i] = calculateGroupElementInZero(groupElements[i], parts, parts[i]);
        }
        return ThresholdSalt.addGroupElementArray(newGroupElements);
    }

    public static byte[] calculateGroupElementInZero(byte[] groupElements, byte[] players, byte player){
        byte[] omega = ThresholdSalt.lagrangeInterpolationInZero(players, player);
        byte[] numerator = ThresholdSalt.byteToScalar((byte) Math.abs(omega[0]));
        byte[] denominator = ThresholdSalt.byteToScalar((byte) Math.abs(omega[1]));

        byte[] multiplier =ThresholdSalt.multiplyScalars(ThresholdSalt.invertScalar(denominator), numerator);
        byte[] out = scalarMultiply(groupElements, multiplier);

        if ( omega[0]<0 ^ omega[1]<0 ){
            out[31] = (byte) (out[31] ^ 0x80);
        }

        return out;
    }

    public static byte[] thresholdSign1(byte[] message) {
        return message;
    }

    public static byte[] thresholdSign2(byte[] m1, byte[] rand) {
        return baseScalarMult(rand);
    }

    public static byte[] thresholdSign3(byte[] m1, byte[][] m2, byte[] publicKey, byte[] parts) {

        byte[] Rand = recombineGroupElements(m2, parts);

        byte[] m3 = new byte[publicKeyLength*2 + m1.length];
        System.arraycopy(publicKey, 0, m3, 0, publicKeyLength);
        System.arraycopy(Rand, 0, m3, publicKeyLength, groupElementLength);
        System.arraycopy(m1, 0, m3, publicKeyLength+groupElementLength, m1.length);
        return  m3;
    }

    public static byte[] thresholdSign4(byte[] m3, byte[] rand, byte[] secretKey) {
        byte[] publicKey = Arrays.copyOfRange(m3, 0, publicKeyLength);
        byte[] Rand = Arrays.copyOfRange(m3, publicKeyLength, publicKeyLength+groupElementLength);
        byte[] message = Arrays.copyOfRange(m3, publicKeyLength+groupElementLength, m3.length);

        byte[] hash = calculateHash(Rand, publicKey, message);
        return calculateSignature(rand, hash, secretKey);
    }

    public static byte[] thresholdSign5(byte[][] m2, byte[] m3, byte[][] m4, byte[][] publicKeys, byte[] parts) {
        byte[] publicKey = Arrays.copyOfRange(m3, 0, publicKeyLength);
        byte[] Rand = Arrays.copyOfRange(m3, publicKeyLength, publicKeyLength*2);
        byte[] message = Arrays.copyOfRange(m3, publicKeyLength*2, m3.length);

        byte[] hash = calculateHash(Rand, publicKey, message);
        for (int i = 0; i < m2.length; i++) {
            byte[] currentPublicKey = Arrays.copyOfRange(publicKeys[i], signatureLength, dualPublicKeyLength);
            if (!validateSignatureSpecial(currentPublicKey, m2[i], m4[i], hash)){
               throw new IllegalArgumentException("Invalid signature");
            }
        }

        byte[][] signatures = new byte[m4.length][];
        for (byte i = 0; i < m4.length; i++) {
            signatures[i] = calculateScalarInZero(m4[i], parts, parts[i]);
        }
        byte[] signature = ThresholdSalt.addScalarArray(signatures);

        byte[] sign = new byte[signatureLength + message.length];
        System.arraycopy(Rand, 0, sign, 0, TweetNaclFast.ScalarMult.groupElementLength);
        System.arraycopy(signature, 0, sign, TweetNaclFast.ScalarMult.groupElementLength,
                TweetNaclFast.ScalarMult.scalarLength);
        System.arraycopy(message, 0, sign, signatureLength, message.length);
        return sign;
    }

    public static byte[] scalarMultiply(byte[] groupElement, byte[] scalar) {
        byte[] newGroupElement = new byte[publicKeyLength];
        long[][] p = createUnpackedGroupElement();
        long[][] q = unpack(groupElement);
        TweetNaclFast.scalarmult(p, q, scalar, 0);
        TweetNaclFast.pack(newGroupElement, p);
        return newGroupElement;
    }

    public static byte[] thresholdDecrypt1(byte[] cipherMessage) {
        return Arrays.copyOfRange(cipherMessage, 0, publicKeyLength);
    }

    public static byte[] thresholdDecrypt2(byte[] d1, byte[] secretKey) {
        if (d1.length != groupElementLength)
            throw new IllegalArgumentException("d1 has the wrong length");
        if (secretKey.length != scalarLength)
            throw new IllegalArgumentException("Secret key has the wrong length");

        return calculateSharedSecret(d1, secretKey);
    }

    public static byte[] thresholdDecrypt3(byte[][] d2, byte[] cipherMessage, byte[] parts) {
        byte[] sharedKey = recombineGroupElements(d2, parts);
        byte[] cipherText = Arrays.copyOfRange(cipherMessage, publicKeyLength,
                cipherMessage.length);
        return decryptWithSharedSecret(cipherText, sharedKey);
    }
}
