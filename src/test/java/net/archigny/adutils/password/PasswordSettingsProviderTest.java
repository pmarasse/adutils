package net.archigny.adutils.password;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.ldap.core.ContextSource;

public class PasswordSettingsProviderTest {

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

        PasswordSettingsProvider provider = new PasswordSettingsProvider();
        
        PasswordSettingsContainerProvider containerProvider = new PasswordSettingsContainerProvider();
        containerProvider.setContextSource(ldapCS);
        containerProvider.setContainerDN(PasswordSettingsContainerProvider.AD_DEFAULT_CONTAINER_RDN + "," + DOMAIN_DN);
        containerProvider.afterPropertiesSet();
        
        DefaultDomainPolicyPasswordSettingsProvider defaultProvider = new DefaultDomainPolicyPasswordSettingsProvider();
        defaultProvider.setContextSource(ldapCS);
        defaultProvider.setDomainDN(DOMAIN_DN);
        defaultProvider.afterPropertiesSet();

        provider.setDefaultPolicyProvider(defaultProvider);
        provider.setPsoContainerProvider(containerProvider);
        provider.afterPropertiesSet();
        
        Map<String,PasswordSettings> policies = provider.getAllPasswordSettings();
        assertNotNull(policies);
        assertEquals(4, policies.size());
        
        PasswordSettings defaultPolicy = policies.get(PasswordSettingsProvider.DEFAULT_POLICY);
        assertNotNull(defaultPolicy);
        
        PasswordSettings existentPolicy = policies.get(PSO_15);
        assertNotSame(defaultPolicy, existentPolicy);
                
    }

    @Test
    public void testGetPasswordSettingsString2003() throws Exception {

        PasswordSettingsProvider provider = new PasswordSettingsProvider();
        
        DefaultDomainPolicyPasswordSettingsProvider defaultProvider = new DefaultDomainPolicyPasswordSettingsProvider();
        defaultProvider.setContextSource(ldapCS);
        defaultProvider.setDomainDN(DOMAIN_DN);
        defaultProvider.afterPropertiesSet();

        provider.setDefaultPolicyProvider(defaultProvider);
        provider.afterPropertiesSet();

        // Get default policy
        PasswordSettings defaultPolicy = provider.getPasswordSettings((String) null);
        assertNotNull(defaultPolicy);
        
        // Get an existent policy => default as AD2003 does not support Container
        PasswordSettings existentPolicy = provider.getPasswordSettings(PSO_15);
        assertSame(defaultPolicy, existentPolicy);
                
    }

    @Test
    public void testGetPasswordSettingsString2008() throws Exception {

        PasswordSettingsProvider provider = new PasswordSettingsProvider();
        
        PasswordSettingsContainerProvider containerProvider = new PasswordSettingsContainerProvider();
        containerProvider.setContextSource(ldapCS);
        containerProvider.setContainerDN(PasswordSettingsContainerProvider.AD_DEFAULT_CONTAINER_RDN + "," + DOMAIN_DN);
        containerProvider.afterPropertiesSet();
        
        DefaultDomainPolicyPasswordSettingsProvider defaultProvider = new DefaultDomainPolicyPasswordSettingsProvider();
        defaultProvider.setContextSource(ldapCS);
        defaultProvider.setDomainDN(DOMAIN_DN);
        defaultProvider.afterPropertiesSet();

        provider.setDefaultPolicyProvider(defaultProvider);
        provider.setPsoContainerProvider(containerProvider);
        provider.afterPropertiesSet();

        // Get default policy
        PasswordSettings defaultPolicy = provider.getPasswordSettings((String) null);
        assertNotNull(defaultPolicy);
        
        // Get an existent policy <> default
        PasswordSettings existentPolicy = provider.getPasswordSettings(PSO_15);
        assertNotSame(defaultPolicy, existentPolicy);
        
        // Get an non-existent policy => default
        PasswordSettings nonExistentPolicy = provider.getPasswordSettings(PSO_NON_EXISTENT);
        assertSame(defaultPolicy, nonExistentPolicy);
        
    }
}
