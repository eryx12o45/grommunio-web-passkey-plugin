<?php

/**
 * Class PasskeyData for managing passkey settings and credentials
 */
class PasskeyData
{
    /**
     * Check if passkey authentication is activated for the current user
     *
     * @return bool True if activated, false otherwise
     */
    public static function isActivated()
    {
        return $GLOBALS["settings"]->get('zarafa/v1/plugins/passkey/activate', false);
    }

    /**
     * Set the activation status of passkey authentication
     *
     * @param bool $activate True to activate, false to deactivate
     */
    public static function setActivate($activate)
    {
        $GLOBALS["settings"]->set('zarafa/v1/plugins/passkey/activate', $activate);
        $GLOBALS["settings"]->saveSettings();
    }

    /**
     * Get stored passkey credentials for the current user
     *
     * @return string JSON encoded credentials or empty string
     */
    public static function getCredentials()
    {
        return $GLOBALS["settings"]->get('zarafa/v1/plugins/passkey/credentials', '');
    }

    /**
     * Set passkey credentials for the current user
     *
     * @param string $credentials JSON encoded credentials
     */
    public static function setCredentials($credentials)
    {
        $GLOBALS["settings"]->set('zarafa/v1/plugins/passkey/credentials', $credentials);
        $GLOBALS["settings"]->saveSettings();
    }

    /**
     * Add a new passkey credential
     *
     * @param array $credential The credential data
     */
    public static function addCredential($credential)
    {
        $credentials = self::getCredentials();
        $credentialArray = $credentials ? json_decode($credentials, true) : [];
        
        if (!is_array($credentialArray)) {
            $credentialArray = [];
        }
        
        $credentialArray[] = $credential;
        self::setCredentials(json_encode($credentialArray));
    }

    /**
     * Remove a passkey credential by ID
     *
     * @param string $credentialId The credential ID to remove
     */
    public static function removeCredential($credentialId)
    {
        $credentials = self::getCredentials();
        $credentialArray = $credentials ? json_decode($credentials, true) : [];
        
        if (!is_array($credentialArray)) {
            return;
        }
        
        $credentialArray = array_filter($credentialArray, function($cred) use ($credentialId) {
            return $cred['id'] !== $credentialId;
        });
        
        self::setCredentials(json_encode(array_values($credentialArray)));
    }

    /**
     * Get all passkey credentials as array
     *
     * @return array Array of credentials
     */
    public static function getCredentialsArray()
    {
        $credentials = self::getCredentials();
        $credentialArray = $credentials ? json_decode($credentials, true) : [];
        
        return is_array($credentialArray) ? $credentialArray : [];
    }

    /**
     * Check if user has any registered passkeys
     *
     * @return bool True if user has passkeys, false otherwise
     */
    public static function hasCredentials()
    {
        $credentials = self::getCredentialsArray();
        return !empty($credentials);
    }

    /**
     * Get WebAuthn configuration settings
     *
     * @return array Configuration array
     */
    public static function getWebAuthnConfig()
    {
        return [
            'rp_id' => $GLOBALS["settings"]->get('zarafa/v1/plugins/passkey/rp_id', ''),
            'rp_name' => $GLOBALS["settings"]->get('zarafa/v1/plugins/passkey/rp_name', 'Grommunio'),
            'timeout' => $GLOBALS["settings"]->get('zarafa/v1/plugins/passkey/timeout', 60000),
            'user_verification' => $GLOBALS["settings"]->get('zarafa/v1/plugins/passkey/user_verification', 'preferred'),
            'authenticator_attachment' => $GLOBALS["settings"]->get('zarafa/v1/plugins/passkey/authenticator_attachment', null)
        ];
    }
}
