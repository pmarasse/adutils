package net.archigny.adutils.password;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.ldap.core.ContextSource;

public class DefaultDomainPolicyPasswordSettingsProviderTest {

    public static final String DOMAIN_DN = "dc=in,dc=archigny,dc=org";

    private Logger             log       = LoggerFactory.getLogger(DefaultDomainPolicyPasswordSettingsProviderTest.class);

    private ContextSource      ldapCS;

    @Before
    public void setUp() throws Exception {

        log.info("Initialise l'application de test à partir du XML spring");
        ApplicationContext testApp = new ClassPathXmlApplicationContext("testapp.xml");
        ldapCS = (ContextSource) testApp.getBean("searchContextSource");

        log.info("ldapCS Initialisée");

    }

    @Test
    public void testGetPasswordSettings() throws Exception {

        DefaultDomainPolicyPasswordSettingsProvider provider = new DefaultDomainPolicyPasswordSettingsProvider();
        provider.setContextSource(ldapCS);
        provider.setDomainDN(DOMAIN_DN);
        provider.afterPropertiesSet();

        PasswordSettings ps = provider.getPasswordSettings();

        assertNotNull(ps);
        assertEquals(I8.MINUTE * 2, ps.getLockoutDuration());
        assertEquals(I8.MINUTE, ps.getLockoutObservationWindow());
        assertEquals(I8.DAY, ps.getMinimumPasswordAge());
        assertEquals(I8.DAY * 760, ps.getMaximumPasswordAge());
        assertEquals(6, ps.getMinimumPasswordLength());
        assertEquals(3, ps.getLockoutThreshold());
        assertFalse(ps.isPasswordComplexity());
    }

    @Test
    public void testCache() throws Exception {

        DefaultDomainPolicyPasswordSettingsProvider provider = new DefaultDomainPolicyPasswordSettingsProvider();
        provider.setContextSource(ldapCS);
        provider.setDomainDN(DOMAIN_DN);
        provider.setRefreshInterval(500);
        provider.afterPropertiesSet();

        @SuppressWarnings("unused")
        PasswordSettings ps = provider.getPasswordSettings();
        long firstFetch = provider.getLastTimeFetched();
        Thread.sleep(300);
        
        ps = provider.getPasswordSettings();
        long secondFetch = provider.getLastTimeFetched();
        Thread.sleep(300);
        
        ps = provider.getPasswordSettings();
        long thirdFetch = provider.getLastTimeFetched();

        assertEquals(firstFetch, secondFetch);
        assertTrue(thirdFetch > secondFetch);

    }
}
