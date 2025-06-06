# Desktop Lockdown

A simple application to lock down distracting apps and websites on Windows. This tool helps restrict access to certain applications and websites that may be distracting, and can only be unlocked with a password.

## Features

- Block specific applications from running
- Block access to distracting websites
- Password protection for unlocking
- Simple and intuitive user interface
- **Remote control from mobile devices**

## Requirements

- Windows 10 or later
- Python 3.7 or later
- Administrator privileges (required for some features)

## Installation

1. Make sure you have Python installed on your system
2. Install the required packages:

```
pip install -r requirements.txt
```

3. Run the application with administrator privileges:

```
python main.py  # For desktop interface
python server.py  # For remote control from mobile devices
```

## Usage

### Desktop Mode

1. **First Run**: On first run, you'll be prompted to set a password. Remember this password as it will be needed to unlock the system or exit when locked.

2. **Adding Applications**: Click "Add Application" and enter the name of the executable (e.g., "chrome.exe", "discord.exe").

3. **Adding Websites**: Click "Add Website" and enter the domain name (e.g., "facebook.com", "youtube.com").

4. **Locking the System**: Click the "Lock System" button to activate the restrictions.

5. **Unlocking the System**: Click "Unlock System" and enter your password to remove restrictions.

6. **Changing Password**: Use the "Change Password" button to update your password.

### Remote Control Mode

1. **Start the Server**: Run `python server.py` with administrator privileges to start the remote control server.

2. **Connect from Mobile**: The server will display a URL (and optionally a QR code) that you can open on your mobile device's browser.

3. **Mobile Interface**: The mobile interface provides the same functionality as the desktop version:
   - Lock/unlock the system
   - Add/remove blocked applications
   - Add/remove blocked websites
   - Change password

4. **Multiple Devices**: Multiple devices can connect to the server simultaneously to control the lockdown.

## Important Notes

- The application needs to be run as administrator to modify the hosts file for website blocking.
- Some anti-virus software may flag the application because it monitors and terminates processes.
- When the system is locked, the application will prevent the blocked applications from running and block access to the specified websites.
- For remote control functionality, both devices must be on the same network.

## Troubleshooting

- If website blocking doesn't work, ensure you're running the app as administrator.
- If application blocking isn't working, make sure you've entered the correct executable name.
- If you forget your password, you'll need to delete the `password.hash` file and restart the application.
- If you can't connect from a mobile device, check that both devices are on the same network and no firewall is blocking the connection.

## Disclaimer

This tool is intended for educational purposes and to help with focus, not for surveillance or control without consent. Always use responsibly. 