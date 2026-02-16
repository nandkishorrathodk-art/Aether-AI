# 📱 AETHER AI - ANDROID APP BUILD GUIDE

**Status**: ✅ Android Project Created  
**Version**: v0.5.0 Android  
**Date**: February 13, 2026

---

## 🎯 What You're Building

A **native Android app** with voice-only interface, identical to desktop version but optimized for mobile.

### ✨ Android Features

- 🎤 **Voice-Only Interface**
- 👋 **Auto-Greeting** on app launch
- 🎨 **Material Design** UI
- 🔊 **Native Speech Recognition**
- 📱 **Optimized for Mobile**
- 🌍 **30+ Languages**
- 🔒 **Runtime Permissions**

---

## 📋 Prerequisites

### 1. Node.js
```
Download: https://nodejs.org/
Version: 18 or higher
```

### 2. Java JDK
```
Download: https://adoptium.net/
Version: JDK 17 (recommended)
```

### 3. Android Studio
```
Download: https://developer.android.com/studio
Install:
  - Android SDK
  - Android SDK Platform-Tools
  - Android Build-Tools 34.0.0
  - Android Emulator (optional)
```

### 4. Environment Variables

Add to **System Environment Variables**:

```
ANDROID_HOME = C:\Users\<YourName>\AppData\Local\Android\Sdk
JAVA_HOME = C:\Program Files\Eclipse Adoptium\jdk-17.x.x

Path:
  - %ANDROID_HOME%\platform-tools
  - %ANDROID_HOME%\tools
  - %JAVA_HOME%\bin
```

**Restart computer after setting variables!**

---

## 🚀 Build Instructions

### Method 1: One-Click Build (Recommended)

```batch
1. Double-click: BUILD_ANDROID.bat
2. Wait 5-10 minutes
3. Get APK from: android\app\build\outputs\apk\release\
```

### Method 2: Manual Build

```batch
# Install dependencies
npm install

# Clean previous builds
cd android
gradlew clean
cd ..

# Build release APK
cd android
gradlew assembleRelease
cd ..
```

---

## 📱 Installation on Android Device

### Step 1: Enable Developer Options
```
1. Open Settings
2. Go to "About Phone"
3. Tap "Build Number" 7 times
4. Developer Options enabled!
```

### Step 2: Enable USB Debugging
```
1. Settings → Developer Options
2. Turn on "USB Debugging"
3. Connect phone to PC via USB
```

### Step 3: Install APK

**Option A - Via USB**:
```batch
# Install directly to connected device
cd android
gradlew installRelease
```

**Option B - Manual Transfer**:
```
1. Copy APK: android\app\build\outputs\apk\release\app-release.apk
2. Transfer to phone (USB/Email/Drive)
3. Tap APK on phone
4. Allow "Install from Unknown Sources"
5. Install
```

---

## 🎨 Project Structure

```
C:\Users\nandk\.zenflow\worktrees\nitro-v-f99b\
│
├── 📁 android/                    # Android native code
│   ├── app/
│   │   ├── src/main/
│   │   │   ├── java/com/aether/ai/
│   │   │   │   ├── MainActivity.kt        # Main activity
│   │   │   │   └── MainApplication.kt    # App entry
│   │   │   ├── res/
│   │   │   │   ├── values/
│   │   │   │   │   ├── strings.xml       # App name
│   │   │   │   │   └── styles.xml        # Theme
│   │   │   │   └── mipmap/               # App icons
│   │   │   └── AndroidManifest.xml       # Permissions
│   │   └── build.gradle                   # App config
│   ├── build.gradle                       # Project config
│   └── settings.gradle                    # Modules
│
├── 📁 mobile/                     # React Native UI
│   └── App.android.js            # Voice-only UI for Android
│
├── 📄 index.android.js           # Android entry point
├── 📄 app.json                   # App metadata
├── 📄 package.json               # Dependencies
└── 📄 BUILD_ANDROID.bat          # Build script
```

---

## 🔧 Configuration

### App Details (app.json)
```json
{
  "name": "AetherAI",
  "displayName": "Aether AI",
  "version": "0.5.0"
}
```

### Permissions (AndroidManifest.xml)
```xml
- RECORD_AUDIO (voice input)
- INTERNET (API calls)
- MODIFY_AUDIO_SETTINGS (TTS)
- VIBRATE (feedback)
- FOREGROUND_SERVICE (background listening)
```

### App Colors
```
Primary: #6366f1 (indigo)
Secondary: #8b5cf6 (purple)
Background: #0f172a (dark blue)
```

---

## 🎤 How the Android App Works

### 1. App Launch
```
App starts → Request microphone permission → Play greeting
"Hello sir, at your service!"
```

### 2. Voice Input
```
User taps mic button → Starts recording
→ Displays "Listening..." with pulse animation
→ User speaks command
→ Converts speech to text (STT)
```

### 3. Backend Processing
```
Sends command to:
http://localhost:8000/api/v1/voice-commands/execute

(You'll need to expose your backend or deploy to cloud)
```

### 4. Voice Output
```
Receives response → Converts text to speech (TTS)
→ Speaks response → Displays in UI
```

---

## 🌐 Backend Connection Options

### Option 1: Localhost (Testing)
```javascript
// For Android Emulator
const API_URL = 'http://10.0.2.2:8000';

// For Real Device on same WiFi
const API_URL = 'http://192.168.x.x:8000';
```

### Option 2: Cloud Deployment (Production)
```javascript
// Deploy Python backend to:
- Railway.app
- Render.com
- AWS/Azure/GCP

const API_URL = 'https://your-backend.com';
```

---

## 📦 Build Outputs

### Debug APK (for testing)
```
Location: android/app/build/outputs/apk/debug/app-debug.apk
Size: ~50-70 MB
Use: Development testing
```

### Release APK (for distribution)
```
Location: android/app/build/outputs/apk/release/app-release.apk
Size: ~30-50 MB (optimized)
Use: Production distribution
```

---

## 🐛 Troubleshooting

### Build Errors

**Error: ANDROID_HOME not set**
```
Solution: Set environment variable and restart computer
```

**Error: Java version mismatch**
```
Solution: Install JDK 17 from https://adoptium.net/
```

**Error: SDK not found**
```
Solution: Open Android Studio → SDK Manager → Install SDK 34
```

**Error: Gradle build failed**
```
Solution:
cd android
gradlew clean
cd ..
Try build again
```

### Runtime Errors

**App crashes on launch**
```
Check: Microphone permission granted in app settings
```

**Voice not working**
```
Check: Microphone permission in Settings → Apps → Aether AI → Permissions
```

**Network error**
```
Check: Backend server is running
Check: API URL is correct in App.android.js
```

---

## 🚀 Next Steps

### After Building APK:

1. **Test on Device**
   - Install APK
   - Grant microphone permission
   - Test voice commands

2. **Deploy Backend**
   - Deploy Python backend to cloud
   - Update API URL in app

3. **Publish to Play Store** (optional)
   - Create Google Play Developer account ($25)
   - Generate signed APK
   - Upload to Play Store
   - Add screenshots, description
   - Submit for review

---

## 📱 System Requirements

**Minimum Android Version**: Android 7.0 (API 24)  
**Target Android Version**: Android 14 (API 34)  
**Recommended RAM**: 2GB+  
**Storage**: 100MB for app

**Your Acer Swift Neo**: Can build APK easily! ✅

---

## 🎯 Features Comparison

| Feature | Desktop (Electron) | Android (Native) |
|---------|-------------------|------------------|
| Voice-Only UI | ✅ | ✅ |
| Auto-Greeting | ✅ | ✅ |
| Modern UI | ✅ | ✅ Material Design |
| Platform | Windows/Mac/Linux | Android 7.0+ |
| Install Size | ~150MB | ~50MB |
| Backend | Local Python | Cloud API |

---

## 💡 Tips

1. **First Build Takes Long**: 10-15 minutes for first build (downloads dependencies)
2. **Subsequent Builds**: 2-3 minutes
3. **Use Emulator**: Test without physical device (Android Studio)
4. **Check Logs**: Use `adb logcat` for debugging
5. **Hot Reload**: Use `npm start` for development

---

## ✅ Build Checklist

Before building:
- [ ] Node.js installed
- [ ] Java JDK 17 installed
- [ ] Android Studio installed
- [ ] ANDROID_HOME set
- [ ] JAVA_HOME set
- [ ] Restarted computer
- [ ] `npm install` completed

Ready to build:
```batch
BUILD_ANDROID.bat
```

---

**🎉 Your Android version of Aether AI is ready to build!**

Just run `BUILD_ANDROID.bat` and you'll have an APK in 5-10 minutes! 📱

---

*Built with ❤️ for Android*  
*February 13, 2026*
