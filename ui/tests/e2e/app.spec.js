const { test, expect } = require('@playwright/test');
const { _electron: electron } = require('playwright');
const path = require('path');

test.describe('Aether AI Desktop Application', () => {
  let electronApp;
  let window;

  test.beforeAll(async () => {
    electronApp = await electron.launch({
      args: [path.join(__dirname, '../../main.js')],
      env: {
        ...process.env,
        NODE_ENV: 'development',
      },
    });

    window = await electronApp.firstWindow();
    await window.waitForLoadState('domcontentloaded');
  });

  test.afterAll(async () => {
    await electronApp.close();
  });

  test('should launch application', async () => {
    const title = await window.title();
    expect(title).toBe('Aether AI');
  });

  test('should display app bar with logo and title', async () => {
    const appBar = window.locator('header');
    await expect(appBar).toBeVisible();

    const title = window.locator('text=AETHER AI');
    await expect(title).toBeVisible();
  });

  test('should show backend status chip', async () => {
    const statusChip = window.locator('text=/Online|Offline|Checking.../');
    await expect(statusChip).toBeVisible();
  });

  test('should display chat interface', async () => {
    const chatInterface = window.locator('text=How can I assist you today?');
    await expect(chatInterface).toBeVisible();
  });

  test('should display voice control button', async () => {
    const voiceButton = window.locator('button[aria-label*="voice"]');
    const micButton = window.locator('svg[data-testid="MicIcon"]');
    
    const isVoiceButtonVisible = await voiceButton.isVisible().catch(() => false);
    const isMicButtonVisible = await micButton.isVisible().catch(() => false);
    
    expect(isVoiceButtonVisible || isMicButtonVisible).toBeTruthy();
  });

  test('should open settings drawer', async () => {
    const settingsButton = window.locator('button[aria-label="Settings"], svg[data-testid="SettingsIcon"]').first();
    await settingsButton.click();

    const settingsDrawer = window.locator('text=Settings').first();
    await expect(settingsDrawer).toBeVisible({ timeout: 5000 });

    const closeButton = window.locator('svg[data-testid="CloseIcon"]').first();
    await closeButton.click();
  });

  test('should have message input field', async () => {
    const inputField = window.locator('textarea[placeholder="Type your message..."]');
    await expect(inputField).toBeVisible();
  });

  test('should have send button', async () => {
    const sendButton = window.locator('svg[data-testid="SendIcon"]');
    await expect(sendButton).toBeVisible();
  });

  test('should allow typing in message input', async () => {
    const inputField = window.locator('textarea[placeholder="Type your message..."]');
    await inputField.fill('Hello, Aether!');
    
    const value = await inputField.inputValue();
    expect(value).toBe('Hello, Aether!');
    
    await inputField.clear();
  });

  test('should show clear conversation button', async () => {
    const clearButton = window.locator('svg[data-testid="DeleteIcon"]');
    await expect(clearButton).toBeVisible();
  });
});

test.describe('Settings functionality', () => {
  let electronApp;
  let window;

  test.beforeAll(async () => {
    electronApp = await electron.launch({
      args: [path.join(__dirname, '../../main.js')],
      env: {
        ...process.env,
        NODE_ENV: 'development',
      },
    });

    window = await electronApp.firstWindow();
    await window.waitForLoadState('domcontentloaded');
  });

  test.afterAll(async () => {
    await electronApp.close();
  });

  test('should display all settings tabs', async () => {
    const settingsButton = window.locator('svg[data-testid="SettingsIcon"]').first();
    await settingsButton.click();

    await window.waitForSelector('text=General', { timeout: 5000 });
    
    const generalTab = window.locator('text=General');
    const voiceTab = window.locator('text=Voice');
    const aiTab = window.locator('text=AI');
    const memoryTab = window.locator('text=Memory');

    await expect(generalTab).toBeVisible();
    await expect(voiceTab).toBeVisible();
    await expect(aiTab).toBeVisible();
    await expect(memoryTab).toBeVisible();

    const closeButton = window.locator('svg[data-testid="CloseIcon"]').first();
    await closeButton.click();
  });

  test('should switch between settings tabs', async () => {
    const settingsButton = window.locator('svg[data-testid="SettingsIcon"]').first();
    await settingsButton.click();

    await window.waitForSelector('text=Voice', { timeout: 5000 });
    
    const voiceTab = window.locator('button:has-text("Voice")');
    await voiceTab.click();

    const sttOption = window.locator('text=Speech Recognition');
    await expect(sttOption).toBeVisible();

    const closeButton = window.locator('svg[data-testid="CloseIcon"]').first();
    await closeButton.click();
  });
});
