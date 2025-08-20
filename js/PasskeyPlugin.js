Ext.namespace('Zarafa.plugins.passkey');

/**
 * @class Zarafa.plugins.passkey.PasskeyPlugin
 * @extends Zarafa.core.Plugin
 */
Zarafa.plugins.passkey.PasskeyPlugin = Ext.extend(Zarafa.core.Plugin, {

    /**
     * @constructor
     * @param {Object} config Configuration object
     */
    constructor: function (config) {
        config = config || {};

        Zarafa.plugins.passkey.PasskeyPlugin.superclass.constructor.call(this, config);
    },

    /**
     * Init plugin
     */
    initPlugin: function () {
        Zarafa.plugins.passkey.PasskeyPlugin.superclass.initPlugin.apply(this, arguments);
        Zarafa.plugins.passkey.data.Configuration.init();
        this.registerInsertionPoint("context.settings.categories", this.createSettingCategories, this);
    },

    /**
     * Create category in settings
     */
    createSettingCategories: function () {
        return {
            xtype: "Zarafa.plugins.passkey.category"
        };
    }
});

Zarafa.onReady(function () {
    let allowUserDisable = container.getSettingsModel().get('zarafa/v1/plugins/passkey/user_disable_allowed');

    container.registerPlugin(new Zarafa.core.PluginMetaData({
        name: 'passkey',
        displayName: _('Passkey Plugin'),
        allowUserDisable: allowUserDisable,
        pluginConstructor: Zarafa.plugins.passkey.PasskeyPlugin
    }));
});
