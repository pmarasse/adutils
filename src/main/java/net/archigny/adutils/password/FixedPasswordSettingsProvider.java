package net.archigny.adutils.password;

import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.InitializingBean;

/**
 * Dummy provider class which provides manually feeded password settings
 * 
 * @author Philippe MARASSE
 */
public final class FixedPasswordSettingsProvider implements IDefaultPasswordSettingsProvider, InitializingBean {

    /**
     * Default PasswordSettings... are not consistent.
     */
    private PasswordSettings ps = new PasswordSettings(false, 0, false, 0, 0, 0, 0, 0, 0);

    @Override
    public PasswordSettings getPasswordSettings() {

        return ps;
    }

    @Override
    public void afterPropertiesSet() throws Exception {

        if (!ps.isValid()) {
            throw new BeanInitializationException("Settings provided are not consistent.");
        }
    }

    // Setters & Getters

    public void setReversibleEncryption(boolean reversibleEncryption) {

        ps.setReversibleEncryption(reversibleEncryption);
    }

    public void setHistoryLength(int historyLength) {

        ps.setHistoryLength(historyLength);
    }

    public void setPasswordComplexity(boolean passwordComplexity) {

        ps.setPasswordComplexity(passwordComplexity);
    }

    public void setMinimumPasswordLength(int minimumPasswordLength) {

        ps.setMinimumPasswordLength(minimumPasswordLength);
    }

    public void setMinimumPasswordAge(long minimumPasswordAge) {

        ps.setMinimumPasswordAge(minimumPasswordAge);
    }

    public void setMaximumPasswordAge(long maximumPasswordAge) {

        ps.setMaximumPasswordAge(maximumPasswordAge);
    }

    public void setLockoutThreshold(int lockoutThreshold) {

        ps.setLockoutThreshold(lockoutThreshold);
    }

    public void setLockoutDuration(long lockoutDuration) {

        ps.setLockoutDuration(lockoutDuration);
    }

    public void setLockoutObservationWindow(long lockoutObservationWindow) {

        ps.setLockoutObservationWindow(lockoutObservationWindow);
    }

}
