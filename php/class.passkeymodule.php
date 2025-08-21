<?php

require_once __DIR__ . "/vendor/autoload.php";
require_once __DIR__ . "/class.passkeydata.settings.php";
require_once __DIR__ . "/class.passkeycredentialrepository.php";

use Webauthn\Server;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\AttestationConveyancePreference;
use Webauthn\UserVerificationRequirement;
use Webauthn\AuthenticatorAttachment;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use Psr\Http\Message\ServerRequestInterface;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;

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

        // Validate the attestation response using WebAuthn library
        $publicKeyCredentialSource = $this->validateAttestationResponse($credentialData);
        
        if (!$publicKeyCredentialSource) {
            $this->sendFeedback(false, array(
                'type' => ERROR_GENERAL,
                'info' => array(
                    'message' => dgettext('plugin_passkey', 'Invalid attestation response')
                )
            ));
            return false;
        }

        // Create credential record with validated data
        $credential = array(
            'id' => $credentialData['id'],
            'name' => $name,
            'rawId' => $credentialData['rawId'],
            'publicKey' => base64_encode($publicKeyCredentialSource->getCredentialPublicKey()),
            'signCount' => $publicKeyCredentialSource->getCounter(),
            'userHandle' => $publicKeyCredentialSource->getUserHandle(),
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

        // Verify the assertion using WebAuthn library
        if ($this->validateAssertionResponse($assertionData, $credential)) {
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
     * Get WebAuthn Server instance
     * @return Server
     */
    private function getWebAuthnServer()
    {
        $config = PasskeyData::getWebAuthnConfig();
        
        // Create Relying Party entity
        $rpEntity = new PublicKeyCredentialRpEntity(
            $config['rp_name'],
            $config['rp_id']
        );
        
        // Create credential source repository
        $credentialRepository = new PasskeyCredentialRepository();
        
        // Create algorithm manager
        $algorithmManager = new Manager();
        $algorithmManager->add(new ES256());
        $algorithmManager->add(new RS256());
        
        // Create server
        return new Server(
            $rpEntity,
            $credentialRepository,
            $algorithmManager
        );
    }

    /**
     * Get user entity for WebAuthn
     * @return PublicKeyCredentialUserEntity
     */
    private function getUserEntity()
    {
        $username = $GLOBALS['mapisession']->getUserName();
        $userId = hash('sha256', $username); // Create consistent user ID
        
        return new PublicKeyCredentialUserEntity(
            $username,
            $userId,
            $username
        );
    }

    /**
     * Validate WebAuthn attestation response
     * @param array $credentialData Credential data from client
     * @return PublicKeyCredentialSource|null
     */
    private function validateAttestationResponse($credentialData)
    {
        try {
            $server = $this->getWebAuthnServer();
            
            // Create PSR-7 request
            $psr17Factory = new Psr17Factory();
            $creator = new ServerRequestCreator(
                $psr17Factory,
                $psr17Factory,
                $psr17Factory,
                $psr17Factory
            );
            
            // Convert credential data to JSON for PSR-7 request
            $jsonData = json_encode($credentialData);
            $request = $creator->fromGlobals()
                ->withBody($psr17Factory->createStream($jsonData))
                ->withHeader('Content-Type', 'application/json');
            
            // Load the public key credential
            $publicKeyCredentialLoader = new PublicKeyCredentialLoader();
            $publicKeyCredential = $publicKeyCredentialLoader->load($jsonData);
            
            // Get the response
            $authenticatorAttestationResponse = $publicKeyCredential->getResponse();
            
            if (!$authenticatorAttestationResponse instanceof AuthenticatorAttestationResponse) {
                return null;
            }
            
            // Create creation options (this should be stored from the registration initiation)
            $userEntity = $this->getUserEntity();
            $credentialParameters = [
                new PublicKeyCredentialParameters('public-key', -7), // ES256
                new PublicKeyCredentialParameters('public-key', -257), // RS256
            ];
            
            $creationOptions = new PublicKeyCredentialCreationOptions(
                $server->getPublicKeyCredentialRpEntity(),
                $userEntity,
                random_bytes(32), // Challenge should be stored from registration initiation
                $credentialParameters
            );
            
            // Validate the attestation response
            $validator = new AuthenticatorAttestationResponseValidator();
            $publicKeyCredentialSource = $validator->check(
                $authenticatorAttestationResponse,
                $creationOptions,
                $request
            );
            
            return $publicKeyCredentialSource;
            
        } catch (Exception $e) {
            error_log("[passkey] Attestation validation error: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Validate WebAuthn assertion response
     * @param array $assertionData Assertion data from client
     * @param array $storedCredential Stored credential data
     * @return boolean
     */
    private function validateAssertionResponse($assertionData, $storedCredential)
    {
        try {
            $server = $this->getWebAuthnServer();
            
            // Create PSR-7 request
            $psr17Factory = new Psr17Factory();
            $creator = new ServerRequestCreator(
                $psr17Factory,
                $psr17Factory,
                $psr17Factory,
                $psr17Factory
            );
            
            // Convert assertion data to JSON for PSR-7 request
            $jsonData = json_encode($assertionData);
            $request = $creator->fromGlobals()
                ->withBody($psr17Factory->createStream($jsonData))
                ->withHeader('Content-Type', 'application/json');
            
            // Load the public key credential
            $publicKeyCredentialLoader = new PublicKeyCredentialLoader();
            $publicKeyCredential = $publicKeyCredentialLoader->load($jsonData);
            
            // Get the response
            $authenticatorAssertionResponse = $publicKeyCredential->getResponse();
            
            if (!$authenticatorAssertionResponse instanceof AuthenticatorAssertionResponse) {
                return false;
            }
            
            // Create request options (this should be stored from the authentication initiation)
            $allowedCredentials = [
                new PublicKeyCredentialDescriptor(
                    'public-key',
                    base64_decode(strtr($storedCredential['rawId'], '-_', '+/'))
                )
            ];
            
            $requestOptions = new PublicKeyCredentialRequestOptions(
                random_bytes(32), // Challenge should be stored from authentication initiation
                60000, // Timeout
                $server->getPublicKeyCredentialRpEntity()->getId(),
                $allowedCredentials,
                UserVerificationRequirement::PREFERRED
            );
            
            // Get the stored credential source
            $credentialRepository = new PasskeyCredentialRepository();
            $publicKeyCredentialSource = $credentialRepository->findOneByCredentialId(
                $publicKeyCredential->getRawId()
            );
            
            if (!$publicKeyCredentialSource) {
                return false;
            }
            
            // Validate the assertion response
            $validator = new AuthenticatorAssertionResponseValidator();
            $publicKeyCredentialSource = $validator->check(
                $publicKeyCredentialSource,
                $authenticatorAssertionResponse,
                $requestOptions,
                $request,
                null // User handle
            );
            
            // Update the credential with new counter value
            $this->updateCredentialCounter($publicKeyCredentialSource);
            
            return true;
            
        } catch (Exception $e) {
            error_log("[passkey] Assertion validation error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Update credential counter after successful authentication
     * @param PublicKeyCredentialSource $credentialSource
     */
    private function updateCredentialCounter($credentialSource)
    {
        $credentials = PasskeyData::getCredentialsArray();
        
        for ($i = 0; $i < count($credentials); $i++) {
            if ($credentials[$i]['rawId'] === base64_encode($credentialSource->getCredentialId())) {
                $credentials[$i]['signCount'] = $credentialSource->getCounter();
                $credentials[$i]['lastUsed'] = time();
                break;
            }
        }
        
        PasskeyData::setCredentials(json_encode($credentials));
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
