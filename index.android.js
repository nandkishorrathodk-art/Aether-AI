/**
 * Aether AI - Android Entry Point
 * Voice-First AI Assistant for Android
 */

import { AppRegistry } from 'react-native';
import App from './mobile/App.android';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);
