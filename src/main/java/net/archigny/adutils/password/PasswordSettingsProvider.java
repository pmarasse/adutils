package net.archigny.adutils.password;

import java.util.HashMap;
import java.util.Map;

import javax.naming.Name;

import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.InitializingBean;

public class PasswordSettingsProvider implements IPasswordSettingsProvider, InitializingBean {

    public static final String               DEFAULT_POLICY = "default";

    /**
     * AD <= 2003 : should be null as Password Settings Container does not exists AD >= 2008 : should be an instance of
     * PasswordSettingsContainerProvider
     */
    private IPasswordSettingsProvider        psoContainerProvider;

    /**
     * AD all versions : should be an instance of DefaultDomainPolicyPasswordProvider
     */
    private IDefaultPasswordSettingsProvider defaultPolicyProvider;

    @Override
    public void afterPropertiesSet() throws Exception {

        if (defaultPolicyProvider == null) {
            throw new BeanInitializationException("defaultPolicyProvider cannot be null");
        }

    }

    @Override
    public Map<String, PasswordSettings> getAllPasswordSettings() {

        // As I don't know if policies have to be refreshed, Creating a new hashmap each time
        HashMap<String, PasswordSettings> result = new HashMap<String, PasswordSettings>();
        result.put(DEFAULT_POLICY, defaultPolicyProvider.getPasswordSettings());
        if (psoContainerProvider != null) {
            result.putAll(psoContainerProvider.getAllPasswordSettings());
        }
        return result;
    }

    @Override
    public PasswordSettings getPasswordSettings(String DN) {

        PasswordSettings result = null;
        if (psoContainerProvider != null) {
            result = psoContainerProvider.getPasswordSettings(DN);
        }
        if (result == null) {
            return defaultPolicyProvider.getPasswordSettings();
        }
        return result;
    }

    @Override
    public PasswordSettings getPasswordSettings(Name name) {

        PasswordSettings result = null;
        if (psoContainerProvider != null) {
            result = psoContainerProvider.getPasswordSettings(name);
        }
        if (result == null) {
            return defaultPolicyProvider.getPasswordSettings();
        }
        return result;
    }

    // Getters and setters
    
    public IPasswordSettingsProvider getPsoContainerProvider() {
    
        return psoContainerProvider;
    }

    
    public void setPsoContainerProvider(IPasswordSettingsProvider psoContainerProvider) {
    
        this.psoContainerProvider = psoContainerProvider;
    }

    
    public IDefaultPasswordSettingsProvider getDefaultPolicyProvider() {
    
        return defaultPolicyProvider;
    }

    
    public void setDefaultPolicyProvider(IDefaultPasswordSettingsProvider defaultPolicyProvider) {
    
        this.defaultPolicyProvider = defaultPolicyProvider;
    }

}
