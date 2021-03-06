package net.archigny.adutils.password.util;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DESKeySpec;

/**
 * Classe inspirée de http://www.codeforge.com/read/69875/NTLM.java__html
 * 
 * @author Philippe MARASSE <philippe.marasse@ch-poitiers.fr>
 * 
 */
public final class PasswordHashes {

    /**
     * The magic number used to compute the Lan Manager hashed password :
     * KGS!@#$%
     */
    public static final byte[] MAGIC = new byte[] { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 };

    /**
     * <p>
     * Converts an unsigned byte to an unsigned integer.
     * </p>
     * <p>
     * Notice that Java bytes are always signed, but the cryptographic
     * algorithms rely on unsigned ones, that can be simulated in this way.<br>
     * A bit mask is employed to prevent that the signum bit is extended to
     * MSBs.
     * </p>
     */
    private static int unsignedByteToInt(byte b) {

        return (int) b & 0xFF;
    }

    /**
     * <p>
     * Computes an odd DES key from 56 bits represented as a 7-bytes array.
     * </p>
     * <p>
     * Keeps elements from index <code>offset</code> to index
     * <code>offset + 7</code> of supplied array.
     * </p>
     * 
     * @param keyData
     *            a byte array containing the 56 bits used to compute the DES
     *            key
     * @param offset
     *            the offset of the first element of the 56-bits key data
     * 
     * @return the odd DES key generated
     * 
     * @exception InvalidKeyException
     * @exception NoSuchAlgorithmException
     * @exception InvalidKeySpecException
     */
    private static Key computeDESKey(byte[] keyData, int offset) throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException {

        byte[] desKeyData = new byte[8];
        int[] k = new int[7];

        for (int i = 0; i < 7; i++)
            k[i] = unsignedByteToInt(keyData[offset + i]);

        desKeyData[0] = (byte) (k[0] >>> 1);
        desKeyData[1] = (byte) (((k[0] & 0x01) << 6) | (k[1] >>> 2));
        desKeyData[2] = (byte) (((k[1] & 0x03) << 5) | (k[2] >>> 3));
        desKeyData[3] = (byte) (((k[2] & 0x07) << 4) | (k[3] >>> 4));
        desKeyData[4] = (byte) (((k[3] & 0x0F) << 3) | (k[4] >>> 5));
        desKeyData[5] = (byte) (((k[4] & 0x1F) << 2) | (k[5] >>> 6));
        desKeyData[6] = (byte) (((k[5] & 0x3F) << 1) | (k[6] >>> 7));
        desKeyData[7] = (byte) (k[6] & 0x7F);

        for (int i = 0; i < 8; i++)
            desKeyData[i] = (byte) (unsignedByteToInt(desKeyData[i]) << 1);

        KeySpec desKeySpec = new DESKeySpec(desKeyData);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        return secretKey;
    }

    /**
     * Converts a byte[] to a lower cased hexadecimal String
     * 
     * @param bytes
     *            [] le tableau à convertir
     * @return String la chaîne convertie en héxadécimal, en minuscules.
     */
    public static String getLowerCaseHexString(byte[] bytes) {

        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Converts a byte[] to a upper cased hexadecimal String
     * 
     * @param bytes
     *            [] le tableau à convertir
     * @return String la chaîne convertie en héxadécimal, en minuscules.
     */
    public static String getUpperCaseHexString(byte[] bytes) {

        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Computes the Lan Manager hashed version of a password.
     * 
     * @param password
     *            the user password
     * 
     * @return the Lan Manager hashed version of the password in a 16-bytes
     *         array
     * 
     * @exception HashComputingException
     *                if a problem is detected during computation
     */
    public static byte[] computeLMPassword(String password) throws IllegalArgumentException, HashComputingException {

        if (password == null)
            throw new IllegalArgumentException("password : null value not allowed");
        
        try {
            // Gets the first 14-bytes of the ASCII upper cased password
            int len = password.length();
            if (len > 14)
                len = 14;
            Cipher c = Cipher.getInstance("DES/ECB/NoPadding");

            byte[] lm_pw = new byte[14];
            byte[] bytes = password.toUpperCase().getBytes();
            int i;
            for (i = 0; i < len; i++)
                lm_pw[i] = bytes[i];
            for (; i < 14; i++)
                lm_pw[i] = 0;

            byte[] lm_hpw = new byte[16];
            // Builds a first DES key with its first 7 bytes
            Key k = computeDESKey(lm_pw, 0);
            c.init(Cipher.ENCRYPT_MODE, k);
            // Hashes the MAGIC number with this key into the first 8 bytes of
            // the result
            c.doFinal(MAGIC, 0, 8, lm_hpw, 0);

            // Repeats the work with the last 7 bytes to gets the last 8 bytes
            // of the result
            k = computeDESKey(lm_pw, 7);
            c.init(Cipher.ENCRYPT_MODE, k);
            c.doFinal(MAGIC, 0, 8, lm_hpw, 8);

            return lm_hpw;
        } catch (InvalidKeySpecException e) {
            throw new HashComputingException("InvalidKeySpecException during Hash computation", e);
        } catch (InvalidKeyException e) {
            throw new HashComputingException("InvalidKeyException during Hash computation", e);
        } catch (BadPaddingException e) {
            throw new HashComputingException("BadPaddingException during Hash computation", e);
        } catch (IllegalBlockSizeException e) {
            throw new HashComputingException("IllegalBlockSizeException during Hash computation", e);
        } catch (ShortBufferException e) {
            throw new HashComputingException("ShortBufferException during Hash computation", e);
        } catch (NoSuchAlgorithmException e) {
            throw new HashComputingException("NoSuchAlgorithmException during Hash computation", e);
        } catch (NoSuchPaddingException e) {
            throw new HashComputingException("NoSuchPaddingException during Hash computation", e);
        }
    }

    /**
     * Computes the Lan Manager hashed version of a password as a lower cased
     * String
     * 
     * @param password
     *            passowrd to be hashed
     * @return Hexadecimal string of LM Hash
     */
    public static String computeLMPasswordAsLowerCaseString(String password) {

        byte[] rawHash = computeLMPassword(password);
        return rawHash == null ? null : getLowerCaseHexString(rawHash);
    }

    /**
     * Computes the Lan Manager hashed version of a password as a upper cased
     * String
     * 
     * @param password
     *            passowrd to be hashed
     * @return Hexadecimal string of LM Hash
     */
    public static String computeLMPasswordAsUpperCaseString(String password) {

        byte[] rawHash = computeLMPassword(password);
        return rawHash == null ? null : getUpperCaseHexString(rawHash);
    }

    /**
     * Computes the NT hashed version of a password.
     * 
     * @param password
     *            the user password
     * 
     * @return the NT hashed version of the password in a 16-bytes array
     * 
     * @exception HashComputingException
     *                if a problem is detected during computation
     */
    public static byte[] computeNTPassword(String password) throws IllegalArgumentException, HashComputingException {

        if (password == null)
            throw new IllegalArgumentException("password : null value not allowed");
        // Gets the first 14-bytes of the UNICODE password
        int len = password.length();
        if (len > 14)
            len = 14;
        byte[] nt_pw = new byte[2 * len];
        for (int i = 0; i < len; i++) {
            char ch = password.charAt(i);
            nt_pw[2 * i] = (byte) ch;
            nt_pw[2 * i + 1] = (byte) ((ch >>> 8) & 0xFF);
        }

        // Return its MD4 digest as the hashed version
        MessageDigest md = new MD4();
        return md.digest(nt_pw);
    }

    /**
     * Computes the NT hashed version of a password as a lower cased String
     * 
     * @param password
     * @return Hashed password as a lower case hexadecimal string
     */
    public static String computeNTPasswordAsLowerCaseString(String password) {

        byte[] rawHash = computeNTPassword(password);
        return rawHash == null ? null : getLowerCaseHexString(rawHash);
    }

    /**
     * Computes the NT hashed version of a password as a upper cased String
     * 
     * @param password
     * @return Hashed password as a lower case hexadecimal string
     */
    public static String computeNTPasswordAsUpperCaseString(String password) {

        byte[] rawHash = computeNTPassword(password);
        return rawHash == null ? null : getUpperCaseHexString(rawHash);
    }
}
