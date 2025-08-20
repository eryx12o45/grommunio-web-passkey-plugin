Ext.namespace('Zarafa.plugins.passkey.settings');

/**
 * @class Zarafa.plugins.passkey.settings.GeneralSettingsWidget
 * @extends Zarafa.settings.ui.SettingsWidget
 * 
 * General settings widget for the Passkey plugin
 */
Zarafa.plugins.passkey.settings.GeneralSettingsWidget = Ext.extend(Zarafa.settings.ui.SettingsWidget, {

    /**
     * @constructor
     * @param {Object} config Configuration object
     */
    constructor: function(config) {
        config = config || {};

        Ext.applyIf(config, {
            title: _('Passkey Settings'),
            layout: 'form',
            items: this.createSettingsItems()
        });

        Zarafa.plugins.passkey.settings.GeneralSettingsWidget.superclass.constructor.call(this, config);
    },

    /**
     * Create the settings form items
     * @return {Array} Array of form items
     */
    createSettingsItems: function() {
        return [{
            xtype: 'displayfield',
            fieldLabel: '',
            value: _('Passkeys provide a secure and convenient way to authenticate without passwords. You can register multiple passkeys and use them to log into your account.'),
            htmlEncode: false,
            cls: 'zarafa-settings-widget-info'
        }, {
            xtype: 'checkbox',
            name: 'zarafa/v1/plugins/passkey/enable',
            fieldLabel: _('Enable Passkey Plugin'),
            boxLabel: _('Enable the passkey authentication plugin'),
            ref: 'enableCheckbox',
            listeners: {
                check: this.onEnableChange,
                scope: this
            }
        }, {
            xtype: 'checkbox',
            name: 'zarafa/v1/plugins/passkey/activate',
            fieldLabel: _('Activate Passkey Authentication'),
            boxLabel: _('Use passkey authentication for login'),
            ref: 'activateCheckbox',
            disabled: true,
            listeners: {
                check: this.onActivateChange,
                scope: this
            }
        }, {
            xtype: 'fieldset',
            title: _('WebAuthn Support'),
            ref: 'webauthnFieldset',
            items: [{
                xtype: 'displayfield',
                ref: '../webauthnStatus',
                fieldLabel: _('Browser Support'),
                value: this.getWebAuthnSupportText()
            }]
        }, {
            xtype: 'fieldset',
            title: _('Registered Passkeys'),
            ref: 'passkeysFieldset',
            disabled: true,
            items: [{
                xtype: 'button',
                text: _('Register New Passkey'),
                ref: '../registerButton',
                handler: this.onRegisterPasskey,
                scope: this,
                disabled: true
            }, {
                xtype: 'grid',
                ref: '../passkeysGrid',
                height: 200,
                store: new Ext.data.ArrayStore({
                    fields: ['id', 'name', 'created', 'lastUsed']
                }),
                columns: [{
                    header: _('Name'),
                    dataIndex: 'name',
                    width: 150
                }, {
                    header: _('Created'),
                    dataIndex: 'created',
                    width: 120,
                    renderer: Ext.util.Format.dateRenderer('Y-m-d H:i')
                }, {
                    header: _('Last Used'),
                    dataIndex: 'lastUsed',
                    width: 120,
                    renderer: function(value) {
                        return value ? Ext.util.Format.date(new Date(value), 'Y-m-d H:i') : _('Never');
                    }
                }, {
                    xtype: 'actioncolumn',
                    width: 50,
                    items: [{
                        icon: 'resources/iconsets/fugue/cross.png',
                        tooltip: _('Delete Passkey'),
                        handler: this.onDeletePasskey,
                        scope: this
                    }]
                }],
                viewConfig: {
                    emptyText: _('No passkeys registered')
                }
            }]
        }];
    },

    /**
     * Initialize the widget
     */
    initEvents: function() {
        Zarafa.plugins.passkey.settings.GeneralSettingsWidget.superclass.initEvents.call(this);
        
        // Load passkeys when widget is initialized
        this.loadPasskeys();
        
        // Update UI based on current settings
        this.updateUI();
    },

    /**
     * Get WebAuthn support status text
     * @return {String} Support status text
     */
    getWebAuthnSupportText: function() {
        var config = Zarafa.plugins.passkey.data.Configuration;
        if (config.checkWebAuthnSupport()) {
            return '<span style="color: green;">' + _('Supported') + '</span>';
        } else {
            return '<span style="color: red;">' + _('Not supported - Please use a modern browser') + '</span>';
        }
    },

    /**
     * Handle enable checkbox change
     * @param {Ext.form.Checkbox} checkbox The checkbox
     * @param {Boolean} checked Whether checked
     */
    onEnableChange: function(checkbox, checked) {
        this.activateCheckbox.setDisabled(!checked);
        this.passkeysFieldset.setDisabled(!checked);
        this.registerButton.setDisabled(!checked || !this.activateCheckbox.getValue());
        
        if (!checked) {
            this.activateCheckbox.setValue(false);
        }
    },

    /**
     * Handle activate checkbox change
     * @param {Ext.form.Checkbox} checkbox The checkbox
     * @param {Boolean} checked Whether checked
     */
    onActivateChange: function(checkbox, checked) {
        this.registerButton.setDisabled(!checked);
        
        if (checked && !Zarafa.plugins.passkey.data.Configuration.checkWebAuthnSupport()) {
            Ext.Msg.alert(_('WebAuthn Not Supported'), _('Your browser does not support WebAuthn. Please use a modern browser to use passkey authentication.'));
            checkbox.setValue(false);
            return;
        }
    },

    /**
     * Handle register passkey button click
     */
    onRegisterPasskey: function() {
        if (!Zarafa.plugins.passkey.data.Configuration.checkWebAuthnSupport()) {
            Ext.Msg.alert(_('WebAuthn Not Supported'), _('Your browser does not support WebAuthn.'));
            return;
        }

        Ext.Msg.prompt(_('Register Passkey'), _('Enter a name for this passkey:'), function(btn, text) {
            if (btn === 'ok' && text) {
                this.registerNewPasskey(text);
            }
        }, this);
    },

    /**
     * Register a new passkey
     * @param {String} name Name for the passkey
     */
    registerNewPasskey: function(name) {
        var config = Zarafa.plugins.passkey.data.Configuration.getWebAuthnConfig();
        var userInfo = Zarafa.plugins.passkey.data.Configuration.getUserInfo();
        var challenge = Zarafa.plugins.passkey.data.Configuration.generateChallenge();

        var createOptions = {
            publicKey: {
                challenge: challenge,
                rp: {
                    id: config.rpId,
                    name: config.rpName
                },
                user: userInfo,
                pubKeyCredParams: [{
                    type: 'public-key',
                    alg: -7 // ES256
                }, {
                    type: 'public-key',
                    alg: -257 // RS256
                }],
                timeout: config.timeout,
                attestation: 'direct',
                authenticatorSelection: {
                    userVerification: config.userVerification
                }
            }
        };

        if (config.authenticatorAttachment) {
            createOptions.publicKey.authenticatorSelection.authenticatorAttachment = config.authenticatorAttachment;
        }

        navigator.credentials.create(createOptions).then(function(credential) {
            var credentialData = {
                id: credential.id,
                rawId: Zarafa.plugins.passkey.data.Configuration.arrayBufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    attestationObject: Zarafa.plugins.passkey.data.Configuration.arrayBufferToBase64Url(credential.response.attestationObject),
                    clientDataJSON: Zarafa.plugins.passkey.data.Configuration.arrayBufferToBase64Url(credential.response.clientDataJSON)
                }
            };

            Zarafa.plugins.passkey.data.ResponseHandler.registerPasskey(credentialData, name, function(success, message) {
                if (success) {
                    Ext.Msg.alert(_('Success'), message);
                    this.loadPasskeys();
                } else {
                    Ext.Msg.alert(_('Error'), message);
                }
            }, this);
        }.createDelegate(this)).catch(function(error) {
            Ext.Msg.alert(_('Error'), _('Failed to create passkey: ') + error.message);
        });
    },

    /**
     * Handle delete passkey
     * @param {Ext.grid.GridPanel} grid The grid
     * @param {Number} rowIndex Row index
     * @param {Number} colIndex Column index
     */
    onDeletePasskey: function(grid, rowIndex, colIndex) {
        var record = grid.getStore().getAt(rowIndex);
        var credentialId = record.get('id');
        var name = record.get('name');

        Ext.Msg.confirm(_('Delete Passkey'), String.format(_('Are you sure you want to delete the passkey "{0}"?'), name), function(btn) {
            if (btn === 'yes') {
                Zarafa.plugins.passkey.data.ResponseHandler.deletePasskey(credentialId, function(success, message) {
                    if (success) {
                        Ext.Msg.alert(_('Success'), message);
                        this.loadPasskeys();
                    } else {
                        Ext.Msg.alert(_('Error'), message);
                    }
                }, this);
            }
        }, this);
    },

    /**
     * Load passkeys from server
     */
    loadPasskeys: function() {
        Zarafa.plugins.passkey.data.ResponseHandler.listPasskeys(function(success, data) {
            if (success) {
                var store = this.passkeysGrid.getStore();
                store.removeAll();
                
                if (Ext.isArray(data)) {
                    Ext.each(data, function(passkey) {
                        store.add(new store.recordType(passkey));
                    });
                }
            }
        }, this);
    },

    /**
     * Update UI based on current settings
     */
    updateUI: function() {
        var enabled = this.enableCheckbox.getValue();
        var activated = this.activateCheckbox.getValue();
        
        this.activateCheckbox.setDisabled(!enabled);
        this.passkeysFieldset.setDisabled(!enabled);
        this.registerButton.setDisabled(!enabled || !activated);
    }
});

Ext.reg('Zarafa.plugins.passkey.settings.GeneralSettingsWidget', Zarafa.plugins.passkey.settings.GeneralSettingsWidget);
