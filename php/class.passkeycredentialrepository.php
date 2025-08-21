<?php

require_once __DIR__ . "/class.passkeydata.settings.php";

use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Credential repository for WebAuthn passkeys
 * Implements the PublicKeyCredentialSourceRepository interface
 */
class PasskeyCredentialRepository implements PublicKeyCredentialSourceRepository
{
    /**
     * Find a credential source by its credential ID
     * @param string $publicKeyCredentialId The credential ID
     * @return PublicKeyCredentialSource|null
     */
    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $credentials = PasskeyData::getCredentialsArray();
        
        foreach ($credentials as $credential) {
            $storedCredentialId = base64_decode(strtr($credential['rawId'], '-_', '+/'));
            
            if ($storedCredentialId === $publicKeyCredentialId) {
                return $this->createCredentialSource($credential);
            }
        }
        
        return null;
    }

    /**
     * Find all credential sources for a user
     * @param PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity The user entity
     * @return PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        $credentials = PasskeyData::getCredentialsArray();
        $sources = [];
        
        foreach ($credentials as $credential) {
            $sources[] = $this->createCredentialSource($credential);
        }
        
        return $sources;
    }

    /**
     * Save a credential source
     * @param PublicKeyCredentialSource $publicKeyCredentialSource The credential source to save
     */
    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $credential = [
            'id' => base64_encode($publicKeyCredentialSource->getCredentialId()),
            'rawId' => base64_encode($publicKeyCredentialSource->getCredentialId()),
            'publicKey' => base64_encode($publicKeyCredentialSource->getCredentialPublicKey()),
            'signCount' => $publicKeyCredentialSource->getCounter(),
            'userHandle' => $publicKeyCredentialSource->getUserHandle(),
            'created' => time(),
            'name' => 'WebAuthn Credential' // Default name, should be set elsewhere
        ];
        
        PasskeyData::addCredential($credential);
    }

    /**
     * Create a PublicKeyCredentialSource from stored credential data
     * @param array $credential Stored credential data
     * @return PublicKeyCredentialSource
     */
    private function createCredentialSource(array $credential): PublicKeyCredentialSource
    {
        $credentialId = base64_decode(strtr($credential['rawId'], '-_', '+/'));
        $publicKey = isset($credential['publicKey']) ? base64_decode(strtr($credential['publicKey'], '-_', '+/')) : '';
        $userHandle = isset($credential['userHandle']) ? $credential['userHandle'] : null;
        $counter = isset($credential['signCount']) ? (int)$credential['signCount'] : 0;
        
        return new PublicKeyCredentialSource(
            $credentialId,
            'public-key',
            [],
            'none',
            $publicKey,
            $userHandle,
            $counter
        );
    }
}
