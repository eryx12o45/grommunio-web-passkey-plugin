# Grommunio Web Passkey Plugin

A WebAuthn passkey authentication plugin for Grommunio Web that enables users to authenticate using passkeys instead of traditional passwords.

## Features

- **WebAuthn Support**: Full WebAuthn implementation for secure passkey authentication
- **Multiple Passkeys**: Users can register and manage multiple passkeys
- **Cross-Platform**: Works with platform authenticators (Touch ID, Face ID, Windows Hello) and cross-platform authenticators (USB security keys)
- **User-Friendly Interface**: Intuitive settings panel for passkey management
- **Secure Storage**: Encrypted storage of passkey credentials
- **Fallback Support**: Option to use password authentication if needed

## Requirements

- Grommunio Web (compatible version)
- Modern web browser with WebAuthn support
- HTTPS connection (required for WebAuthn)
- PHP 7.4 or higher

## Installation

1. Copy the plugin files to your Grommunio Web plugins directory:
   ```bash
   cp -r grommunio-web-passkey-plugin /path/to/grommunio-web/plugins/passkey
   ```

2. Configure the plugin by editing `config.php`:
   ```php
   // Set your domain for the Relying Party ID
   const PLUGIN_PASSKEY_RP_ID = 'your-domain.com';
   
   // Set your organization name
   const PLUGIN_PASSKEY_RP_NAME = 'Your Organization';
   ```

3. Enable the plugin in your Grommunio Web configuration.

4. Install PHP dependencies (if using Composer):
   ```bash
   cd plugins/passkey/php
   composer install
   ```

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

### WebAuthn Settings

- **RP_ID**: Must match your domain name (e.g., 'example.com')
- **RP_NAME**: Human-readable name for your organization
- **TIMEOUT**: Time in milliseconds for WebAuthn operations
- **USER_VERIFICATION**: 'required', 'preferred', or 'discouraged'
- **AUTHENTICATOR_ATTACHMENT**: 'platform', 'cross-platform', or null

## Usage

### For Users

1. **Enable the Plugin**:
   - Go to Settings → Passkey Authentication
   - Check "Enable Passkey Plugin"

2. **Register a Passkey**:
   - Check "Activate Passkey Authentication"
   - Click "Register New Passkey"
   - Enter a name for your passkey
   - Follow your browser's prompts to create the passkey

3. **Login with Passkey**:
   - When logging in, you'll be prompted to use your passkey
   - Follow your browser's authentication prompts
   - Option to fall back to password authentication if needed

4. **Manage Passkeys**:
   - View all registered passkeys in the settings
   - Delete passkeys you no longer need
   - See when each passkey was created and last used

### For Administrators

1. **Global Settings**:
   - Configure default settings in `config.php`
   - Set organization-wide policies
   - Control user access to the plugin

2. **Security Considerations**:
   - Ensure HTTPS is enabled (required for WebAuthn)
   - Configure proper CORS headers if needed
   - Monitor passkey usage and security events

## Browser Support

The plugin requires browsers with WebAuthn support:

- **Chrome/Chromium**: Version 67+
- **Firefox**: Version 60+
- **Safari**: Version 14+
- **Edge**: Version 18+

## Security Features

- **Cryptographic Authentication**: Uses public-key cryptography
- **Phishing Resistant**: Passkeys are bound to the origin
- **No Shared Secrets**: Private keys never leave the user's device
- **Replay Attack Protection**: Each authentication is unique
- **User Verification**: Optional biometric or PIN verification

## Troubleshooting

### Common Issues

1. **WebAuthn Not Supported**:
   - Ensure you're using a modern browser
   - Check that HTTPS is enabled
   - Verify the browser supports WebAuthn

2. **Registration Fails**:
   - Check that RP_ID matches your domain
   - Ensure HTTPS is properly configured
   - Verify no browser extensions are interfering

3. **Authentication Fails**:
   - Check that the passkey hasn't been deleted
   - Verify the user's authenticator is working
   - Ensure the browser can access the authenticator

### Debug Mode

Enable debug logging by adding to your PHP configuration:
```php
error_reporting(E_ALL);
ini_set('display_errors', 1);
```

Check browser console for JavaScript errors and network requests.

## Development

### Building the Plugin

1. Install dependencies:
   ```bash
   npm install
   ```

2. Build the JavaScript files:
   ```bash
   npm run build
   ```

3. Lint the code:
   ```bash
   npm run lint
   ```

### File Structure

```
passkey/
├── config.php                 # Plugin configuration
├── manifest.xml              # Plugin manifest
├── package.json              # Node.js dependencies
├── js/                       # JavaScript files
│   ├── PasskeyPlugin.js      # Main plugin class
│   ├── data/                 # Data handling
│   │   ├── Configuration.js  # WebAuthn configuration
│   │   └── ResponseHandler.js # Server communication
│   └── settings/             # Settings UI
│       ├── Category.js       # Settings category
│       └── GeneralSettingsWidget.js # Settings widget
├── php/                      # PHP backend
│   ├── plugin.passkey.php    # Main plugin class
│   ├── class.passkeymodule.php # Module handler
│   └── class.passkeydata.settings.php # Data management
└── resources/                # Static resources
    └── css/
        └── passkey.css       # Plugin styles
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This plugin is licensed under the AGPL-3.0 License. See the LICENSE file for details.

## Support

For support and bug reports, please use the issue tracker or contact the Grommunio support team.

## Changelog

### Version 1.0.0
- Initial release
- WebAuthn passkey authentication
- Multiple passkey support
- Settings management interface
- Cross-platform authenticator support
