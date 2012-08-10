package net.archigny.adutils.password;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.ldap.core.ContextSource;

public class PasswordSettingsContainerProviderTest {

    private Logger             log              = LoggerFactory.getLogger(DefaultDomainPolicyPasswordSettingsProviderTest.class);

    public static final String DOMAIN_DN        = "dc=in,dc=archigny,dc=org";

    public static final String PSO_15           = "cn=passe 15j";

    public static final String PSO_APPS         = "cn=comptes-applicatifs";

    public static final String PSO_TEST         = "cn=test";

    public static final String PSO_NON_EXISTENT = "non-existent";

    public static final String CONTAINER_DN     = "CN=Password Settings Container,CN=System,DC=in,DC=archigny,DC=org";

    private ContextSource      ldapCS;

    @Before
    public void setUp() throws Exception {

        log.info("Initialise l'application de test à partir du XML spring");
        ApplicationContext testApp = new ClassPathXmlApplicationContext("testapp.xml");
        ldapCS = (ContextSource) testApp.getBean("searchContextSource");

        log.info("ldapCS Initialisée");

    }

    @Test
    public void testGetAllPasswordSettings() throws Exception {

        PasswordSettingsContainerProvider provider = new PasswordSettingsContainerProvider();
        try {
            provider.afterPropertiesSet();
            fail("No contextSource should have triggered an exception");
        } catch (BeanInitializationException e) {
        }

        provider.setContextSource(ldapCS);
        provider.setContainerDN(PasswordSettingsContainerProvider.AD_DEFAULT_CONTAINER_RDN + "," + DOMAIN_DN);
        provider.afterPropertiesSet();

        log.info("Recherche à la base : " + provider.getContainerDN());

        Map<String, PasswordSettings> policies = provider.getAllPasswordSettings();
        assertFalse(policies.isEmpty());
        assertEquals(3, policies.size());
        assertTrue(policies.containsKey(PSO_15));
        assertTrue(policies.containsKey(PSO_APPS));
        assertTrue(policies.containsKey(PSO_TEST));

        PasswordSettings psoApps = policies.get(PSO_APPS);
        assertEquals(I8.NEVER, psoApps.getMaximumPasswordAge());
        assertEquals(0, psoApps.getMinimumPasswordAge());
        assertEquals(16, psoApps.getMinimumPasswordLength());
        assertFalse(psoApps.isPasswordComplexity());
        assertFalse(psoApps.isReversibleEncryption());
        assertEquals(0, psoApps.getLockoutDuration());
        assertEquals(0, psoApps.getLockoutObservationWindow());
        assertEquals(0, psoApps.getLockoutThreshold());

    }

    @Test
    public void testGetPasswordSettingsString() throws Exception {

        PasswordSettingsContainerProvider provider = new PasswordSettingsContainerProvider();
        provider.setContextSource(ldapCS);
        provider.setContainerDN(PasswordSettingsContainerProvider.AD_DEFAULT_CONTAINER_RDN + "," + DOMAIN_DN);
        provider.afterPropertiesSet();

        String psoTestName = PSO_TEST + "," + CONTAINER_DN;

        PasswordSettings pso = provider.getPasswordSettings(psoTestName);
        assertNotNull(pso);

        assertEquals(I8.DAY * 60 + I8.HOUR * 10 + I8.MINUTE * 20 + I8.SECOND * 30, pso.getMaximumPasswordAge());
        assertEquals(I8.DAY, pso.getMinimumPasswordAge());
        assertEquals(8, pso.getMinimumPasswordLength());
        assertTrue(pso.isPasswordComplexity());
        assertTrue(pso.isReversibleEncryption());
        assertEquals(I8.MINUTE * 10 + I8.SECOND * 12, pso.getLockoutDuration());
        assertEquals(I8.MINUTE * 5 + I8.SECOND * 10, pso.getLockoutObservationWindow());
        assertEquals(4, pso.getLockoutThreshold());
        assertEquals(5, pso.getHistoryLength());

        assertNull(provider.getPasswordSettings(PSO_NON_EXISTENT));

    }

    @Test
    public void testCache() throws Exception {

        PasswordSettingsContainerProvider provider = new PasswordSettingsContainerProvider();
        provider.setContextSource(ldapCS);
        provider.setContainerDN(PasswordSettingsContainerProvider.AD_DEFAULT_CONTAINER_RDN + "," + DOMAIN_DN);
        provider.setRefreshInterval(500);
        provider.afterPropertiesSet();

        String psoTestName = PSO_TEST + "," + CONTAINER_DN;

        PasswordSettings pso = provider.getPasswordSettings(psoTestName);
        assertNotNull(pso);

        long firstFetch = provider.getLastTimeFetched();
        Thread.sleep(300);
        
        pso = provider.getPasswordSettings(psoTestName);
        long secondFetch = provider.getLastTimeFetched();
        Thread.sleep(300);
        
        pso = provider.getPasswordSettings(psoTestName);
        long thirdFetch = provider.getLastTimeFetched();
        
        assertEquals(firstFetch, secondFetch);
        assertTrue(thirdFetch > secondFetch);
        
    }

}
