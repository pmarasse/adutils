package net.archigny.adutils.password;

import static org.junit.Assert.*;
import net.archigny.adutils.password.I8;

import org.junit.Test;

public class I8Test {

    /**
     * 2012-08-08 13:41 CET (four trailing zeroes needed : conversion to
     * timestamp looses some resolution)
     */
    public final static long REF_I8 = 129888996667350000L;

    @Test
    public void conversionTest() {

        long now = System.currentTimeMillis();

        assertEquals(now, I8.convertToEpoch(I8.convertToI8(now)));

        // We're loosing in resolution...
        assertEquals(REF_I8, I8.convertToI8(I8.convertToEpoch(REF_I8)));

    }
}
