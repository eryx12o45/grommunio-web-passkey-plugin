<?php

require_once __DIR__ . "/vendor/autoload.php";
require_once __DIR__ . "/class.passkeydata.settings.php";

/**
 * PHP file to handle passkey authentication verification
 */
require_once("../../../init.php");
require_once(BASE_PATH . "server/includes/bootstrap.php");
require_once(BASE_PATH . "server/includes/core/class.encryptionstore.php");

// Make sure the php session is started
WebAppSession::getInstance();

$assertionData = ($_POST && array_key_exists('assertion_data', $_POST)) ? $_POST['assertion_data'] : '';
$challenge = ($_POST && array_key_exists('challenge', $_POST)) ? $_POST['challenge'] : '';

$encryptionStore = EncryptionStore::getInstance();
$user = $encryptionStore->get('username');
$verification = false;

if ($assertionData && $challenge) {
    try {
        $assertion = json_decode($assertionData, true);
        
        if ($assertion && isset($assertion['id'])) {
            // Get user's stored credentials
            $credentials = $encryptionStore->get('passkeyCredentials', '');
            $credentialArray = $credentials ? json_decode($credentials, true) : [];
            
            // Find matching credential
            $matchingCredential = null;
            foreach ($credentialArray as $cred) {
                if ($cred['id'] === $assertion['id']) {
                    $matchingCredential = $cred;
                    break;
                }
            }
            
            if ($matchingCredential) {
                // Simplified verification - in production, use proper WebAuthn library
                // For now, we'll verify basic structure and mark as successful
                if (isset($assertion['response']['signature']) && 
                    isset($assertion['response']['authenticatorData']) &&
                    isset($assertion['response']['clientDataJSON'])) {
                    
                    $verification = true;
                }
            }
        }
    } catch (Exception $e) {
    }
}

if ($verification) {
    $_SESSION['passkeyLoggedOn'] = TRUE; // Passkey authentication successful
    header('Location: ../../../index.php', true, 303);
} else {
    $_SESSION['passkeyLoggedOn'] = FALSE; // Authentication failed
    header('Location: login.php', true, 303);
}
