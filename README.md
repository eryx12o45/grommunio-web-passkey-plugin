# Grommunio Web Passkey Plugin

A WebAuthn passkey authentication plugin for Grommunio Web that enables users to authenticate using passkeys instead of traditional passwords.

# Requirements

* Modern web browser with WebAuthn support
* make (to build plugin)
* NodeJS >=18
* PHP >=8.2

# How to install plugin

* Check out the repository locally
* Execute ``npm install``
* Execute ```make DESTDIR=./passkey```
* Copy folder ```passkey``` to your Grommunio Webmail's plugin folder ``[default: /usr/share/grommunio-web/plugins]``
* As default the plugin is enabled for each user, but needs to be activated separately in the plugin configuration


## Configuration

### Basic Configuration

Edit `config.php` to customize the plugin behavior:

```php
// Enable/disable the plugin for new users
const PLUGIN_PASSKEY_ENABLE = true;

// Force enable the plugin (users cannot disable it)
const PLUGIN_PASSKEY_ALWAYS_ENABLED = false;

// Activate passkey authentication by default for new users
const PLUGIN_PASSKEY_ACTIVATE = false;

// Force activate passkey authentication
const PLUGIN_PASSKEY_ALWAYS_ACTIVATED = false;

// WebAuthn configuration
const PLUGIN_PASSKEY_RP_ID = 'your-domain.com';
const PLUGIN_PASSKEY_RP_NAME = 'Your Organization';
const PLUGIN_PASSKEY_TIMEOUT = 60000; // 60 seconds
const PLUGIN_PASSKEY_USER_VERIFICATION = 'preferred';
const PLUGIN_PASSKEY_AUTHENTICATOR_ATTACHMENT = null;
```
