package net.archigny.adutils.password.util;

import static org.junit.Assert.*;

import org.junit.Test;

public class PasswordHashesTest {

    public final static String ClearText = "cactus";
    
    public final static String LM_AS_STRING = "B1DC175E764DE464AAD3B435B51404EE";
    
    public final static String NT_AS_STRING = "8CD722FACF1BB9DAB8D9B1307B536217";
    
    @Test
    public void LMTest() {
        assertEquals(LM_AS_STRING, PasswordHashes.computeLMPasswordAsString(ClearText).toUpperCase());
    }
    
    @Test
    public void NTTest() {
        assertEquals(NT_AS_STRING, PasswordHashes.computeNTPasswordAsString(ClearText).toUpperCase());
    }
                          
}
