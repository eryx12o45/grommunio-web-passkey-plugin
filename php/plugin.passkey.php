<?php

require_once __DIR__ . "/vendor/autoload.php";
require_once __DIR__ . "/class.passkeydata.settings.php";

/**
 * PHP Class plugin Passkey for WebAuthn authentication
 *
 * @class PluginPasskey
 * @extends Plugin
 */
class PluginPasskey extends Plugin
{
    /**
     * Function initializes the Plugin and registers all hooks
     */
    function init()
    {
        $this->registerHook('server.core.settings.init.before');
        $this->registerHook('server.index.load.main.before');
    }

    /**
     * Function is executed when a hook is triggered by the PluginManager
     *
     * @param string $eventID the id of the triggered hook
     * @param mixed $data object(s) related to the hook
     */
    public function execute($eventID, &$data)
    {
        switch ($eventID) {
            case 'server.core.settings.init.before' :
                $this->injectPluginSettings($data);
                break;

            case 'server.index.load.main.before' : // don't use the logon trigger because we need the settings
                try {
                    if (PLUGIN_PASSKEY_ALWAYS_ENABLED) {
                        $GLOBALS["settings"]->set('zarafa/v1/plugins/passkey/enable', true);
                        $GLOBALS["settings"]->saveSettings();
                    }

                    if (PLUGIN_PASSKEY_ALWAYS_ACTIVATED)
                        PasskeyData::setActivate(true);

                    // Check, if user has enabled plugin and has activated passkey authentication
                    if (!$GLOBALS["settings"]->get('zarafa/v1/plugins/passkey/enable')
                        || !PasskeyData::isActivated())
                        break;

                    // Check, if WebAuthn authentication is already done (example: attachment-upload)
                    if (array_key_exists('passkeyLoggedOn', $_SESSION) && $_SESSION['passkeyLoggedOn']) {

                        // Login successful - save or remove challenge
                        if (isset($_SESSION['passkeyChallenge'])) {
                            unset($_SESSION['passkeyChallenge']);
                        }
                        break;
                    }

                    // Save data in session for WebAuthn authentication with login.php and logon.php
                    $encryptionStore = EncryptionStore::getInstance();
                    $encryptionStore->add('passkeyCredentials', PasskeyData::getCredentials());
                    $_SESSION['passkeyEcho']['msgAuthenticatePasskey'] = dgettext('plugin_passkey', 'Authenticate with your passkey');
                    $_SESSION['passkeyEcho']['msgAuthenticationFailed'] = dgettext('plugin_passkey', 'Authentication failed. Please try again.');
                    $_SESSION['passkeyEcho']['butAuthenticate'] = dgettext('plugin_passkey', 'Authenticate');
                    $_SESSION['passkeyEcho']['butCancel'] = dgettext('plugin_passkey', 'Cancel');
                    $_SESSION['passkeyEcho']['butUsePassword'] = dgettext('plugin_passkey', 'Use password instead');

                    // Call passkey login page
                    header('Location: plugins/passkey/php/login.php', true, 303); // delete GLOBALS, go to passkey page
                    exit; // don't execute header-function in index.php

                } catch (Exception $e) {
                    $mess = $e->getFile() . ":" . $e->getLine() . "<br />" . $e->getMessage();
                    error_log("[passkey]: " . $mess);
                    die($mess);
                }
        }
    }

    /**
     * Inject default plugin settings
     *
     * @param mixed $data Reference to the data of the triggered hook
     */
    function injectPluginSettings(&$data)
    {
        $data['settingsObj']->addSysAdminDefaults(array(
            'zarafa' => array(
                'v1' => array(
                    'plugins' => array(
                        'passkey' => array(
                            'enable' => PLUGIN_PASSKEY_ENABLE,
                            'user_disable_allowed' => !PLUGIN_PASSKEY_ALWAYS_ENABLED,
                            'credentials' => '',
                            'activate' => PLUGIN_PASSKEY_ACTIVATE,
                            'rp_id' => PLUGIN_PASSKEY_RP_ID,
                            'rp_name' => PLUGIN_PASSKEY_RP_NAME,
                            'timeout' => PLUGIN_PASSKEY_TIMEOUT,
                            'user_verification' => PLUGIN_PASSKEY_USER_VERIFICATION,
                            'authenticator_attachment' => PLUGIN_PASSKEY_AUTHENTICATOR_ATTACHMENT
                        )
                    )
                )
            )
        ));
    }
}
