package net.archigny.adutils.password.util;

import static org.junit.Assert.*;

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Arrays;
import java.util.Set;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PasswordHashesTest {

    private static final Logger log              = LoggerFactory.getLogger(PasswordHashesTest.class);

    public final static String  PW1_CLEARTEST    = "cactus";

    public final static String  PW1_LM_AS_STRING = "B1DC175E764DE464AAD3B435B51404EE";

    public final static byte[]  PW1_LM_AS_BYTEA  = { (byte) 0xb1, (byte) 0xdc, 0x17, 0x5E, 0x76, 0x4D, (byte) 0xE4, 0x64,
            (byte) 0xAA, (byte) 0xD3, (byte) 0xB4, 0x35, (byte) 0xB5, 0x14, 0x04, (byte) 0xEE };

    public final static String  PW1_NT_AS_STRING = "8CD722FACF1BB9DAB8D9B1307B536217";

    @Test
    public void LMTest() {

        byte[] res = PasswordHashes.computeLMPassword(PW1_CLEARTEST);
        log.info("Résultat : " + PasswordHashes.getHexString(res));
        log.info("Attendu  : " + PasswordHashes.getHexString(PW1_LM_AS_BYTEA));
        assertTrue(Arrays.equals(PW1_LM_AS_BYTEA, res));
        assertEquals(PW1_LM_AS_STRING, PasswordHashes.computeLMPasswordAsString(PW1_CLEARTEST).toUpperCase());
    }

    @Test
    public void NTTest() {

        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            log.info(provider.getInfo());
            Set<Service> services = provider.getServices();
            for (Service service : services) {
                log.info(" => " + service.getAlgorithm());
            }
        }

        assertEquals(PW1_NT_AS_STRING, PasswordHashes.computeNTPasswordAsString(PW1_CLEARTEST).toUpperCase());
    }

}
