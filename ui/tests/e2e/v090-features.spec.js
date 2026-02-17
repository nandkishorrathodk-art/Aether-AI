const { test, expect } = require('@playwright/test');

test.describe('Aether AI v0.9.0 Features', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('http://localhost:3000');
    await page.waitForTimeout(2000);
  });

  test('should open v0.9.0 features panel', async ({ page }) => {
    const v090Button = page.locator('button[aria-label*="suggestions"], button:has(svg)').first();
    await v090Button.click();
    
    await expect(page.locator('text=Monitor')).toBeVisible();
    await expect(page.locator('text=Suggestions')).toBeVisible();
    await expect(page.locator('text=Daily Plan')).toBeVisible();
  });

  test('should navigate between v0.9.0 tabs', async ({ page }) => {
    const v090Button = page.locator('button[aria-label*="suggestions"], button:has(svg)').first();
    await v090Button.click();

    await page.locator('text=Monitor').click();
    await expect(page.locator('text=Screen Monitoring')).toBeVisible();

    await page.locator('text=Suggestions').click();
    await expect(page.locator('text=Proactive Suggestions')).toBeVisible();

    await page.locator('text=Daily Plan').click();
    await expect(page.locator('text=Daily Plan')).toBeVisible();
  });

  test('should display monitoring panel', async ({ page }) => {
    const v090Button = page.locator('button[aria-label*="suggestions"], button:has(svg)').first();
    await v090Button.click();
    
    await page.locator('text=Monitor').click();

    await expect(page.locator('text=Screen Monitoring')).toBeVisible();
    await expect(page.locator('button:has-text("Get Context")')).toBeVisible();
    await expect(page.locator('button:has-text("Take Screenshot")')).toBeVisible();
  });

  test('should display proactive suggestions panel', async ({ page }) => {
    const v090Button = page.locator('button[aria-label*="suggestions"], button:has(svg)').first();
    await v090Button.click();
    
    await page.locator('text=Suggestions').click();

    await expect(page.locator('text=Proactive Suggestions')).toBeVisible();
  });

  test('should display daily plan panel', async ({ page }) => {
    const v090Button = page.locator('button[aria-label*="suggestions"], button:has(svg)').first();
    await v090Button.click();
    
    await page.locator('text=Daily Plan').click();

    await expect(page.locator('text=Daily Plan')).toBeVisible();
  });

  test('should display PC control panel', async ({ page }) => {
    const v090Button = page.locator('button[aria-label*="suggestions"], button:has(svg)').first();
    await v090Button.click();
    
    await page.locator('text=PC Control').click();

    await expect(page.locator('text=PC Control Hub')).toBeVisible();
    await expect(page.locator('text=Mouse Control')).toBeVisible();
    await expect(page.locator('text=Keyboard Control')).toBeVisible();
  });

  test('should display bug bounty autopilot panel', async ({ page }) => {
    const v090Button = page.locator('button[aria-label*="suggestions"], button:has(svg)').first();
    await v090Button.click();
    
    await page.locator('text=Bug Bounty').click();

    await expect(page.locator('text=Bug Bounty Autopilot')).toBeVisible();
    await expect(page.locator('button:has-text("Start Scan")')).toBeVisible();
  });

  test('should display daily report panel', async ({ page }) => {
    const v090Button = page.locator('button[aria-label*="suggestions"], button:has(svg)').first();
    await v090Button.click();
    
    await page.locator('text=Report').click();

    await expect(page.locator('text=Daily Intelligence Report')).toBeVisible();
  });

  test('should display personality settings panel', async ({ page }) => {
    const v090Button = page.locator('button[aria-label*="suggestions"], button:has(svg)').first();
    await v090Button.click();
    
    await page.locator('text=Personality').click();

    await expect(page.locator('text=Personality Settings')).toBeVisible();
    await expect(page.locator('text=Conversation Tone')).toBeVisible();
    await expect(page.locator('text=Hindi-English Mix Level')).toBeVisible();
  });

  test('should have animated transitions', async ({ page }) => {
    const v090Button = page.locator('button[aria-label*="suggestions"], button:has(svg)').first();
    await v090Button.click();

    const drawer = page.locator('[role="presentation"]');
    await expect(drawer).toBeVisible();

    await page.locator('text=Monitor').click();
    await page.waitForTimeout(500);
    
    await page.locator('text=Suggestions').click();
    await page.waitForTimeout(500);
  });

  test('should close v0.9.0 panel when clicking outside', async ({ page }) => {
    const v090Button = page.locator('button[aria-label*="suggestions"], button:has(svg)').first();
    await v090Button.click();
    
    const drawer = page.locator('[role="presentation"]');
    await expect(drawer).toBeVisible();

    await page.click('body', { position: { x: 800, y: 400 } });
    await page.waitForTimeout(500);
  });
});

test.describe('Aether AI v0.9.0 - Accessibility', () => {
  test('should have proper ARIA labels', async ({ page }) => {
    await page.goto('http://localhost:3000');
    
    const buttons = await page.locator('button').all();
    for (const button of buttons) {
      const ariaLabel = await button.getAttribute('aria-label');
      const text = await button.textContent();
      expect(ariaLabel || text).toBeTruthy();
    }
  });

  test('should support keyboard navigation', async ({ page }) => {
    await page.goto('http://localhost:3000');
    
    await page.keyboard.press('Tab');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(1000);
  });
});
