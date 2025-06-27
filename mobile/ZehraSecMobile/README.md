# ZehraShield Mobile App

This directory contains the React Native mobile application for ZehraShield remote management.

## Features

- Real-time threat monitoring
- Push notifications for security alerts
- Remote firewall control
- Dashboard analytics
- Incident management
- Biometric authentication

## Setup

1. Install dependencies:
```bash
npm install
```

2. For iOS development:
```bash
cd ios && pod install
```

3. Run on Android:
```bash
npm run android
```

4. Run on iOS:
```bash
npm run ios
```

## Requirements

- Node.js 16+
- React Native CLI
- Android Studio (for Android)
- Xcode (for iOS)

## Configuration

Configure the API endpoint in `src/config/api.js` to point to your ZehraShield server.

## Build

- Android: `npm run build:android`
- iOS: `npm run build:ios`

For full mobile app implementation, see the ZehraShield documentation.
