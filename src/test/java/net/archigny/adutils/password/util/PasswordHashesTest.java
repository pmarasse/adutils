package net.archigny.adutils.password.util;

import static org.junit.Assert.*;

import java.util.Arrays;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PasswordHashesTest {

    private static final Logger log              = LoggerFactory.getLogger(PasswordHashesTest.class);

    public final static String  PW1_CLEARTEXT    = "cactus";

    public final static String  PW1_LM_AS_STRING = "B1DC175E764DE464AAD3B435B51404EE";

    public final static byte[]  PW1_LM_AS_BYTEA  = { (byte) 0xb1, (byte) 0xdc, 0x17, 0x5E, 0x76, 0x4D, (byte) 0xE4,
            0x64, (byte) 0xAA, (byte) 0xD3, (byte) 0xB4, 0x35, (byte) 0xB5, 0x14, 0x04, (byte) 0xEE };

    public final static String  PW1_NT_AS_STRING = "8CD722FACF1BB9DAB8D9B1307B536217";

    public final static byte[]  PW1_NT_AS_BYTEA  = { (byte) 0x8C, (byte) 0xD7, 0x22, (byte) 0xFA, (byte) 0xCF,
            0x1B, (byte) 0xB9, (byte) 0xDA, (byte) 0xB8, (byte) 0xD9, (byte) 0xB1, 0x30, 0x7B, 0x53, 0x62, 0x17 };

    /**
     * Deux fois 7 caractères pour mettre en évidence la "sécurité" du hash LM
     */
    public static final String  PW2_CLEARTEXT    = "M45Z*65M45Z*65";

    /**
     * Hash LM de 2 fois 16 caractères
     */
    public static final String  PW2_LM_AS_STRING = "C2E51DF490B64E13C2E51DF490B64E13";

    public static final byte[]  PW2_LM_AS_BYTEA  = { (byte) 0xC2, (byte) 0xE5, 0x1D, (byte) 0xF4, (byte) 0x90, 
        (byte) 0xB6, 0x4E, 0x13, (byte) 0xC2, (byte) 0xE5, 0x1D, (byte) 0xF4, (byte) 0x90, (byte) 0xB6, 0x4E, 0x13 };
    
    public static final String  PW2_NT_AS_STRING = "7483F8A08D5649A66D009A7E9E6B6525";

    public static final byte[]  PW2_NT_AS_BYTEA  = { 0x74, (byte) 0x83, (byte) 0xF8, (byte) 0xA0, (byte) 0x8D, 
        0x56, 0x49, (byte) 0xA6, 0x6D, 0x00, (byte) 0x9A, 0x7E, (byte) 0x9E, 0x6B, 0x65, 0x25 };
  
    /**
     * Mot de passe à accent... à valider !
     */
    public static final String  PW3_CLEARTEXT    = "mdpàaccent";
    
    public static final String  PW3_LM_AS_STRING = "2D16B1AFA9B363E0EEEBFE1952CA6AEB";
    
    public static final String  PW3_NT_AS_STRING = "9EBAE58BD33C2DE36B81B2B8AC5C5DAC";
    
    @Test
    public void LMTest() {

        byte[] res = PasswordHashes.computeLMPassword(PW1_CLEARTEXT);
        log.info("Test LMHash du premier mot de passe");
        assertTrue(Arrays.equals(PW1_LM_AS_BYTEA, res));
        assertEquals(PW1_LM_AS_STRING.toLowerCase(), PasswordHashes.computeLMPasswordAsLowerCaseString(PW1_CLEARTEXT));
        assertEquals(PW1_LM_AS_STRING, PasswordHashes.computeLMPasswordAsUpperCaseString(PW1_CLEARTEXT));

        log.info("Test LMHash du second mot de passe");
        assertTrue(Arrays.equals(PW2_LM_AS_BYTEA, PasswordHashes.computeLMPassword(PW2_CLEARTEXT)));
        assertEquals(PW2_LM_AS_STRING.toLowerCase(), PasswordHashes.computeLMPasswordAsLowerCaseString(PW2_CLEARTEXT));
        assertEquals(PW2_LM_AS_STRING, PasswordHashes.computeLMPasswordAsUpperCaseString(PW2_CLEARTEXT));

//        log.info("Test LMHash du troisième mot de passe");
//        assertEquals(PW3_LM_AS_STRING.toLowerCase(), PasswordHashes.computeLMPasswordAsLowerCaseString(PW3_CLEARTEXT));
//        assertEquals(PW3_LM_AS_STRING, PasswordHashes.computeLMPasswordAsUpperCaseString(PW3_CLEARTEXT));
    }

    @Test
    public void NTTest() {

        /*
         * Liste les providers pour vérifier que MD4 **n'est pas** dans la liste
         * !!
         * 
         * Provider[] providers = Security.getProviders(); for (Provider
         * provider : providers) { log.info(provider.getInfo()); Set<Service>
         * services = provider.getServices(); for (Service service : services) {
         * log.info(" => " + service.getAlgorithm()); } }
         */
        log.info("Test NTHash du premier mot de passe");
        assertTrue(Arrays.equals(PW1_NT_AS_BYTEA, PasswordHashes.computeNTPassword(PW1_CLEARTEXT)));
        assertEquals(PW1_NT_AS_STRING.toLowerCase(), PasswordHashes.computeNTPasswordAsLowerCaseString(PW1_CLEARTEXT));
        assertEquals(PW1_NT_AS_STRING, PasswordHashes.computeNTPasswordAsUpperCaseString(PW1_CLEARTEXT));

        log.info("Test NTHash du second mot de passe");
        assertTrue(Arrays.equals(PW2_NT_AS_BYTEA, PasswordHashes.computeNTPassword(PW2_CLEARTEXT)));
        assertEquals(PW2_NT_AS_STRING.toLowerCase(), PasswordHashes.computeNTPasswordAsLowerCaseString(PW2_CLEARTEXT));
        assertEquals(PW2_NT_AS_STRING, PasswordHashes.computeNTPasswordAsUpperCaseString(PW2_CLEARTEXT));
        
//        log.info("Test NTHash du troisième mot de passe");
//        assertEquals(PW3_NT_AS_STRING.toLowerCase(), PasswordHashes.computeNTPasswordAsLowerCaseString(PW3_CLEARTEXT));
//        assertEquals(PW3_NT_AS_STRING, PasswordHashes.computeNTPasswordAsUpperCaseString(PW3_CLEARTEXT));
    }

}
