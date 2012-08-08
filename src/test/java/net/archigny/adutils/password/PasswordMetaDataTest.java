package net.archigny.adutils.password;

import static org.junit.Assert.*;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Locale;

import net.archigny.adutils.password.I8;
import net.archigny.adutils.password.PasswordMetaData;
import net.archigny.adutils.password.PasswordSettings;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PasswordMetaDataTest {

    private static final Logger log           = LoggerFactory.getLogger(PasswordMetaDataTest.class);

    // Constante prise depuis AD : 2012-08-08
    public final static long    REF_LAST_SET  = 129888871432515000L;

    // 2012-08-08 13:41 CET
    public final static long    REF_LAST_SET2 = 129888996667358750L;

    /**
     * Calendar used by tests
     */
    private Calendar            cal;

    /**
     * Date formatter to display results
     */
    private SimpleDateFormat    df;

    @Before
    public void setUp() {

        cal = Calendar.getInstance();
        df = new SimpleDateFormat("dd/MM/yy kk:mm:ss.S Z", Locale.FRANCE);
    }

    @Test
    public void testGetLastSetFromEpoch() {

        PasswordMetaData meta = new PasswordMetaData(REF_LAST_SET);

        log.info("Locale TimeZone: " + cal.getTimeZone().getDisplayName());
        cal.setTimeInMillis(meta.getLastSetFromEpoch());
        log.info("Date calculée : " + df.format(cal.getTime()));

        assertEquals(8, cal.get(Calendar.DAY_OF_MONTH));
        assertEquals(Calendar.AUGUST, cal.get(Calendar.MONTH));
        assertEquals(2012, cal.get(Calendar.YEAR));

        meta = new PasswordMetaData(REF_LAST_SET2);
        cal.setTimeInMillis(meta.getLastSetFromEpoch());
        log.info("Date 2 calculée : " + df.format(cal.getTime()));

        assertEquals(8, cal.get(Calendar.DAY_OF_MONTH));
        assertEquals(Calendar.AUGUST, cal.get(Calendar.MONTH));
        assertEquals(2012, cal.get(Calendar.YEAR));
        assertEquals(13, cal.get(Calendar.HOUR_OF_DAY));
        assertEquals(41, cal.get(Calendar.MINUTE));
        assertEquals(06, cal.get(Calendar.SECOND));
        assertEquals(735, cal.get(Calendar.MILLISECOND));

    }

    @Test
    public void testGetExpirationTime() {

        long now = System.currentTimeMillis();
        
        // Create a dummy pwdLastSet 90 days ago
        long pwdLastSet = I8.convertToI8(now) + 90 * I8.DAY;
        PasswordMetaData meta = new PasswordMetaData(pwdLastSet);
        cal.setTimeInMillis(I8.convertToEpoch(pwdLastSet));
        log.info("pwdLastSet used : " + df.format(cal.getTime()));

        // PSO has 90 day maximum age for password
        PasswordSettings pso = new PasswordSettings(false, 0, false, 8, 0, 90 * I8.DAY, 5, 5 * I8.MINUTE, 2 * I8.MINUTE);

        long expirationTime = meta.getExpirationTime(pso);
        assertEquals(now, expirationTime);
        
        // Older => expired password by 1 hour
        pwdLastSet += I8.HOUR;
        meta = new PasswordMetaData(pwdLastSet);
        
        assertTrue(meta.getExpirationTime(pso) < now);
        assertEquals(3600000, now - meta.getExpirationTime(pso));
        
        // Newer : not expired yet (just wait 1 hour)
        pwdLastSet -= 2 * I8.HOUR;
        meta = new PasswordMetaData(pwdLastSet);
        
        assertTrue(meta.getExpirationTime(pso) > now);
        assertEquals(3600000, meta.getExpirationTime(pso) - now);
        
    }

}
