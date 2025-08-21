<?php

require_once __DIR__ . "/class.passkeydata.settings.php";

/**
 * Passkey Module for handling WebAuthn operations
 *
 * @class PasskeyModule
 * @extends Module
 */
class PasskeyModule extends Module
{
    /**
     * @constructor
     * @param int $id unique id.
     * @param array $data list of all actions.
     */
    public function __construct($id, $data)
    {
        parent::__construct($id, $data);
    }

    /**
     * Executes all the actions in the $data variable.
     * @return boolean true on success or false on failure.
     */
    public function execute()
    {
        $result = false;

        foreach ($this->data as $actionType => $action) {
            if (isset($action["passkey_action"])) {
                try {
                    switch ($action["passkey_action"]) {
                        case "register":
                            $result = $this->registerPasskey($action);
                            break;
                        case "authenticate":
                            $result = $this->authenticatePasskey($action);
                            break;
                        case "delete":
                            $result = $this->deletePasskey($action);
                            break;
                        case "list":
                            $result = $this->listPasskeys($action);
                            break;
                        case "activate":
                            $result = $this->activate();
                            break;
                        case "isactivated":
                            $result = $this->isActivated();
                            break;
                        default:
                            $this->sendFeedback(false, array(
                                'type' => ERROR_GENERAL,
                                'info' => array(
                                    'message' => dgettext('plugin_passkey', 'Unknown action')
                                )
                            ));
                    }
                } catch (Exception $e) {
                    $this->sendFeedback(false, array(
                        'type' => ERROR_GENERAL,
                        'info' => array(
                            'message' => dgettext('plugin_passkey', 'An error occurred: ') . $e->getMessage()
                        )
                    ));
                }
            } else {
                if (isset($actionType)) {
                    try {
                        switch ($actionType) {
                            case "activate":
                                $result = $this->activate();
                                break;
                            case "isactivated":
                                $result = $this->isActivated();
                                break;
                            default:
                                $this->sendFeedback(false, array(
                                    'type' => ERROR_GENERAL,
                                    'info' => array(
                                        'message' => dgettext('plugin_passkey', 'Unknown action')
                                    )
                                ));
                        }
                    } catch (Exception $e) {
                        $this->sendFeedback(false, array(
                            'type' => ERROR_GENERAL,
                            'info' => array(
                                'message' => dgettext('plugin_passkey', 'An error occurred: ') . $e->getMessage()
                            )
                        ));
                    }
                }
            }
        }

        return $result;
    }

    /**
     * Register a new passkey
     * @param array $action Action data
     * @return boolean Success status
     */
    private function registerPasskey($action)
    {
        if (!isset($action['credential_data']) || !isset($action['name'])) {
            $this->sendFeedback(false, array(
                'type' => ERROR_GENERAL,
                'info' => array(
                    'message' => dgettext('plugin_passkey', 'Missing credential data or name')
                )
            ));
            return false;
        }

        $credentialData = json_decode($action['credential_data'], true);
        $name = $action['name'];

        if (!$credentialData) {
            $this->sendFeedback(false, array(
                'type' => ERROR_GENERAL,
                'info' => array(
                    'message' => dgettext('plugin_passkey', 'Invalid credential data')
                )
            ));
            return false;
        }

        // Validate the credential data structure
        if (!isset($credentialData['id']) || !isset($credentialData['rawId']) || 
            !isset($credentialData['response']['attestationObject']) || 
            !isset($credentialData['response']['clientDataJSON'])) {
            $this->sendFeedback(false, array(
                'type' => ERROR_GENERAL,
                'info' => array(
                    'message' => dgettext('plugin_passkey', 'Invalid credential structure')
                )
            ));
            return false;
        }

        // Create credential record
        $credential = array(
            'id' => $credentialData['id'],
            'name' => $name,
            'rawId' => $credentialData['rawId'],
            'publicKey' => $this->extractPublicKey($credentialData['response']['attestationObject']),
            'signCount' => 0,
            'created' => time()
        );

        // Add credential to user's passkeys
        PasskeyData::addCredential($credential);

        $this->sendFeedback(true, array(
            'success' => true,
            'message' => dgettext('plugin_passkey', 'Passkey registered successfully')
        ));

        return true;
    }

    /**
     * Authenticate with passkey
     * @param array $action Action data
     * @return boolean Success status
     */
    private function authenticatePasskey($action)
    {
        if (!isset($action['assertion_data'])) {
            $this->sendFeedback(false, array(
                'type' => ERROR_GENERAL,
                'info' => array(
                    'message' => dgettext('plugin_passkey', 'Missing assertion data')
                )
            ));
            return false;
        }

        $assertionData = json_decode($action['assertion_data'], true);

        if (!$assertionData) {
            $this->sendFeedback(false, array(
                'type' => ERROR_GENERAL,
                'info' => array(
                    'message' => dgettext('plugin_passkey', 'Invalid assertion data')
                )
            ));
            return false;
        }

        // Validate assertion data structure
        if (!isset($assertionData['id']) || !isset($assertionData['response']['signature']) || 
            !isset($assertionData['response']['authenticatorData']) || 
            !isset($assertionData['response']['clientDataJSON'])) {
            $this->sendFeedback(false, array(
                'type' => ERROR_GENERAL,
                'info' => array(
                    'message' => dgettext('plugin_passkey', 'Invalid assertion structure')
                )
            ));
            return false;
        }

        // Find the credential
        $credentials = PasskeyData::getCredentialsArray();
        $credential = null;
        
        foreach ($credentials as $cred) {
            if ($cred['id'] === $assertionData['id']) {
                $credential = $cred;
                break;
            }
        }

        if (!$credential) {
            $this->sendFeedback(false, array(
                'type' => ERROR_GENERAL,
                'info' => array(
                    'message' => dgettext('plugin_passkey', 'Credential not found')
                )
            ));
            return false;
        }

        // Verify the assertion (simplified verification)
        if ($this->verifyAssertion($assertionData, $credential)) {
            $this->sendFeedback(true, array(
                'success' => true,
                'message' => dgettext('plugin_passkey', 'Authentication successful')
            ));

            return true;
        } else {
            $this->sendFeedback(false, array(
                'type' => ERROR_GENERAL,
                'info' => array(
                    'message' => dgettext('plugin_passkey', 'Authentication failed')
                )
            ));
            return false;
        }
    }

    /**
     * Delete a passkey
     * @param array $action Action data
     * @return boolean Success status
     */
    private function deletePasskey($action)
    {
        if (!isset($action['credential_id'])) {
            $this->sendFeedback(false, array(
                'type' => ERROR_GENERAL,
                'info' => array(
                    'message' => dgettext('plugin_passkey', 'Missing credential ID')
                )
            ));
            return false;
        }

        $credentialId = $action['credential_id'];
        PasskeyData::removeCredential($credentialId);

        $this->sendFeedback(true, array(
            'success' => true,
            'message' => dgettext('plugin_passkey', 'Passkey deleted successfully')
        ));

        return true;
    }

    /**
     * List user's passkeys
     * @param array $action Action data
     * @return boolean Success status
     */
    private function listPasskeys($action)
    {
        $credentials = PasskeyData::getCredentialsArray();
        
        // Remove sensitive data before sending to client
        $safeCredentials = array();
        foreach ($credentials as $cred) {
            $safeCredentials[] = array(
                'id' => $cred['id'],
                'name' => $cred['name'],
                'created' => $cred['created']
            );
        }

        $this->sendFeedback(true, array(
            'success' => true,
            'passkeys' => $safeCredentials
        ));

        return true;
    }

    /**
     * Extract public key from attestation object (simplified)
     * @param string $attestationObject Base64URL encoded attestation object
     * @return string Base64URL encoded public key
     */
    private function extractPublicKey($attestationObject)
    {
        // This is a simplified implementation
        // In a production environment, you would use a proper CBOR decoder
        // and WebAuthn library to extract the public key
        return $attestationObject; // Placeholder
    }

    /**
     * Verify WebAuthn assertion (simplified)
     * @param array $assertionData Assertion data
     * @param array $credential Stored credential
     * @return boolean Verification result
     */
    private function verifyAssertion($assertionData, $credential)
    {
        // This is a simplified implementation
        // In a production environment, you would:
        // 1. Verify the client data JSON
        // 2. Verify the authenticator data
        // 3. Verify the signature using the stored public key
        // 4. Check the signature counter
        
        // For now, we'll do basic validation
        return isset($assertionData['response']['signature']) && 
               isset($assertionData['response']['authenticatorData']) &&
               $assertionData['id'] === $credential['id'];
    }

    /**
     * Update a credential in storage
     * @param array $credential Updated credential data
     */
    private function updateCredential($credential)
    {
        $credentials = PasskeyData::getCredentialsArray();
        
        for ($i = 0; $i < count($credentials); $i++) {
            if ($credentials[$i]['id'] === $credential['id']) {
                $credentials[$i] = $credential;
                break;
            }
        }
        
        PasskeyData::setCredentials(json_encode($credentials));
    }

    /**
     * Send feedback to client
     * @param boolean $success Success status
     * @param array $data Response data
     * @param boolean $addResponseDataToBus Whether to add response data to bus
     */
    public function sendFeedback($success = false, $data = [], $addResponseDataToBus = true)
    {
        $response = array_merge(array('success' => $success), $data);
        $this->addActionData("passkey", $response);
        if ($addResponseDataToBus) {
            $GLOBALS["bus"]->addData($this->getResponseData());
        }
    }

    /**
     * Toggle activate/deactivate two-factor authentication
     *
     * @access private
     * @return boolean
     * @throws Exception
     */
    private function activate(): bool
    {
        $isActivated = PasskeyData::isActivated();
        PasskeyData::setActivate(!$isActivated);
        $response = array();
        $response['isActivated'] = !$isActivated;
        $this->addActionData("activate", $response);
        $GLOBALS["bus"]->addData($this->getResponseData());
        return true;
    }

    /**
     * Send if two-factor authentication is activated
     *
     * @access private
     * @return boolean
     * @throws Exception
     */
    private function isActivated(): bool
    {
        $isActivated = PasskeyData::isActivated();
        $response = array();
        $response['isActivated'] = $isActivated;
        $this->addActionData("isactivated", $response);
        $GLOBALS["bus"]->addData($this->getResponseData());
        return true;
    }
}
