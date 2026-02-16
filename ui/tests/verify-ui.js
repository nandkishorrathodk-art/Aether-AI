const fs = require('fs');
const path = require('path');

console.log('='.repeat(60));
console.log('Aether AI - Desktop UI Verification');
console.log('='.repeat(60));
console.log();

let passed = 0;
let failed = 0;
const errors = [];

function checkFile(filepath, description) {
  const fullPath = path.join(__dirname, '..', filepath);
  if (fs.existsSync(fullPath)) {
    console.log(`✓ ${description}`);
    passed++;
    return true;
  } else {
    console.log(`✗ ${description} - File not found: ${filepath}`);
    failed++;
    errors.push(`Missing: ${filepath}`);
    return false;
  }
}

function checkDirectory(dirpath, description) {
  const fullPath = path.join(__dirname, '..', dirpath);
  if (fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory()) {
    console.log(`✓ ${description}`);
    passed++;
    return true;
  } else {
    console.log(`✗ ${description} - Directory not found: ${dirpath}`);
    failed++;
    errors.push(`Missing directory: ${dirpath}`);
    return false;
  }
}

function checkPackageScript(scriptName, description) {
  const packagePath = path.join(__dirname, '..', 'package.json');
  const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  
  if (packageJson.scripts && packageJson.scripts[scriptName]) {
    console.log(`✓ ${description}`);
    passed++;
    return true;
  } else {
    console.log(`✗ ${description} - Script not found: ${scriptName}`);
    failed++;
    errors.push(`Missing script: ${scriptName}`);
    return false;
  }
}

function checkPackageDependency(depName, description) {
  const packagePath = path.join(__dirname, '..', 'package.json');
  const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  
  const allDeps = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };
  
  if (allDeps[depName]) {
    console.log(`✓ ${description}`);
    passed++;
    return true;
  } else {
    console.log(`✗ ${description} - Dependency not found: ${depName}`);
    failed++;
    errors.push(`Missing dependency: ${depName}`);
    return false;
  }
}

console.log('Core Files:');
console.log('-'.repeat(60));
checkFile('package.json', 'Package.json exists');
checkFile('main.js', 'Electron main process exists');
checkFile('preload.js', 'Electron preload script exists');
checkFile('.env', 'Environment configuration exists');
checkFile('playwright.config.js', 'Playwright configuration exists');

console.log();
console.log('React Components:');
console.log('-'.repeat(60));
checkFile('src/App.js', 'Main App component exists');
checkFile('src/components/ChatInterface.jsx', 'ChatInterface component exists');
checkFile('src/components/VoiceControl.jsx', 'VoiceControl component exists');
checkFile('src/components/Settings.jsx', 'Settings component exists');
checkFile('src/components/Notifications.jsx', 'Notifications component exists');

console.log();
console.log('Services:');
console.log('-'.repeat(60));
checkFile('src/services/api.js', 'API client service exists');

console.log();
console.log('Tests:');
console.log('-'.repeat(60));
checkFile('tests/e2e/app.spec.js', 'E2E test suite exists');
checkDirectory('tests', 'Tests directory exists');

console.log();
console.log('Scripts:');
console.log('-'.repeat(60));
checkPackageScript('start', 'Start script available');
checkPackageScript('dev', 'Dev script available');
checkPackageScript('build', 'Build script available');
checkPackageScript('test:e2e', 'E2E test script available');
checkPackageScript('package', 'Package script available');

console.log();
console.log('Dependencies:');
console.log('-'.repeat(60));
checkPackageDependency('react', 'React installed');
checkPackageDependency('electron', 'Electron installed');
checkPackageDependency('@mui/material', 'Material-UI installed');
checkPackageDependency('axios', 'Axios installed');
checkPackageDependency('socket.io-client', 'Socket.IO client installed');
checkPackageDependency('@playwright/test', 'Playwright installed');
checkPackageDependency('electron-store', 'Electron Store installed');

console.log();
console.log('Node Modules:');
console.log('-'.repeat(60));
checkDirectory('node_modules', 'Dependencies installed in node_modules');
checkDirectory('node_modules/react', 'React modules present');
checkDirectory('node_modules/electron', 'Electron modules present');
checkDirectory('node_modules/@mui/material', 'Material-UI modules present');

console.log();
console.log('='.repeat(60));
console.log('Verification Results:');
console.log('='.repeat(60));
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log();

if (failed > 0) {
  console.log('Errors:');
  errors.forEach(err => console.log(`  - ${err}`));
  console.log();
  process.exit(1);
} else {
  console.log('✓ All checks passed! Desktop UI is ready.');
  console.log();
  console.log('Next steps:');
  console.log('  1. Ensure backend is running: cd .. && python src/main.py');
  console.log('  2. Start dev server: npm run dev');
  console.log('  3. Run E2E tests: npm run test:e2e');
  console.log();
  process.exit(0);
}
