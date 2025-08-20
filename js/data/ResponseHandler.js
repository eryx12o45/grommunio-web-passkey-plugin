Ext.namespace('Zarafa.plugins.passkey.data');

/**
 * @class Zarafa.plugins.passkey.data.ResponseHandler
 * @extends Object
 * 
 * Response handler for Passkey plugin server communication
 */
Zarafa.plugins.passkey.data.ResponseHandler = {

    /**
     * Handle passkey registration response
     * @param {Object} response Server response
     * @param {Function} callback Callback function
     * @param {Object} scope Callback scope
     */
    handleRegistrationResponse: function(response, callback, scope) {
        if (response && response.success) {
            if (callback) {
                callback.call(scope || this, true, response.message || _('Passkey registered successfully'));
            }
        } else {
            var errorMsg = response && response.message ? response.message : _('Failed to register passkey');
            if (callback) {
                callback.call(scope || this, false, errorMsg);
            }
        }
    },

    /**
     * Handle passkey authentication response
     * @param {Object} response Server response
     * @param {Function} callback Callback function
     * @param {Object} scope Callback scope
     */
    handleAuthenticationResponse: function(response, callback, scope) {
        if (response && response.success) {
            if (callback) {
                callback.call(scope || this, true, response.message || _('Authentication successful'));
            }
        } else {
            var errorMsg = response && response.message ? response.message : _('Authentication failed');
            if (callback) {
                callback.call(scope || this, false, errorMsg);
            }
        }
    },

    /**
     * Handle passkey deletion response
     * @param {Object} response Server response
     * @param {Function} callback Callback function
     * @param {Object} scope Callback scope
     */
    handleDeletionResponse: function(response, callback, scope) {
        if (response && response.success) {
            if (callback) {
                callback.call(scope || this, true, response.message || _('Passkey deleted successfully'));
            }
        } else {
            var errorMsg = response && response.message ? response.message : _('Failed to delete passkey');
            if (callback) {
                callback.call(scope || this, false, errorMsg);
            }
        }
    },

    /**
     * Handle passkey list response
     * @param {Object} response Server response
     * @param {Function} callback Callback function
     * @param {Object} scope Callback scope
     */
    handleListResponse: function(response, callback, scope) {
        if (response && response.success) {
            var passkeys = response.passkeys || [];
            if (callback) {
                callback.call(scope || this, true, passkeys);
            }
        } else {
            var errorMsg = response && response.message ? response.message : _('Failed to load passkeys');
            if (callback) {
                callback.call(scope || this, false, errorMsg);
            }
        }
    },

    /**
     * Send request to server
     * @param {String} action Action to perform
     * @param {Object} data Request data
     * @param {Function} callback Callback function
     * @param {Object} scope Callback scope
     */
    sendRequest: function(action, data, callback, scope) {
        var requestData = Ext.apply({
            zarafa_action: 'passkey',
            passkey_action: action
        }, data || {});

        container.getRequest().singleRequest(
            'passkeymodule',
            'passkey',
            requestData,
            new Zarafa.core.data.AbstractResponseHandler({
                doPasskey: function(response) {
                    switch (action) {
                        case 'register':
                            this.handleRegistrationResponse(response, callback, scope);
                            break;
                        case 'authenticate':
                            this.handleAuthenticationResponse(response, callback, scope);
                            break;
                        case 'delete':
                            this.handleDeletionResponse(response, callback, scope);
                            break;
                        case 'list':
                            this.handleListResponse(response, callback, scope);
                            break;
                        default:
                            if (callback) {
                                callback.call(scope || this, false, _('Unknown action'));
                            }
                    }
                }.createDelegate(this)
            })
        );
    },

    /**
     * Register a new passkey
     * @param {Object} credentialData WebAuthn credential data
     * @param {String} name Friendly name for the passkey
     * @param {Function} callback Callback function
     * @param {Object} scope Callback scope
     */
    registerPasskey: function(credentialData, name, callback, scope) {
        this.sendRequest('register', {
            credential_data: JSON.stringify(credentialData),
            name: name
        }, callback, scope);
    },

    /**
     * Authenticate with passkey
     * @param {Object} assertionData WebAuthn assertion data
     * @param {Function} callback Callback function
     * @param {Object} scope Callback scope
     */
    authenticatePasskey: function(assertionData, callback, scope) {
        this.sendRequest('authenticate', {
            assertion_data: JSON.stringify(assertionData)
        }, callback, scope);
    },

    /**
     * Delete a passkey
     * @param {String} credentialId Credential ID to delete
     * @param {Function} callback Callback function
     * @param {Object} scope Callback scope
     */
    deletePasskey: function(credentialId, callback, scope) {
        this.sendRequest('delete', {
            credential_id: credentialId
        }, callback, scope);
    },

    /**
     * Get list of user's passkeys
     * @param {Function} callback Callback function
     * @param {Object} scope Callback scope
     */
    listPasskeys: function(callback, scope) {
        this.sendRequest('list', {}, callback, scope);
    }
};
