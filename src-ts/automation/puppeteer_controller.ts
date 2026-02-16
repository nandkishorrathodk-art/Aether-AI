/**
 * Puppeteer Browser Automation Controller
 * Advanced web automation - Better than Vy!
 */

// Note: Install with: npm install puppeteer puppeteer-extra puppeteer-extra-plugin-stealth

interface BrowserOptions {
  headless?: boolean;
  width?: number;
  height?: number;
}

interface ElementSelector {
  selector: string;
  type?: 'css' | 'xpath' | 'text';
}

export class PuppeteerController {
  private browser: any = null;
  private currentPage: any = null;
  
  /**
   * Launch browser instance
   */
  async launch(options: BrowserOptions = {}): Promise<void> {
    try {
      const puppeteer = require('puppeteer-extra');
      const StealthPlugin = require('puppeteer-extra-plugin-stealth');
      
      puppeteer.use(StealthPlugin());
      
      this.browser = await puppeteer.launch({
        headless: options.headless ?? false,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          `--window-size=${options.width || 1920},${options.height || 1080}`
        ],
        defaultViewport: {
          width: options.width || 1920,
          height: options.height || 1080
        }
      });
      
      console.log('✓ Browser launched successfully');
    } catch (error) {
      console.error('Failed to launch browser:', error);
      throw error;
    }
  }
  
  /**
   * Navigate to URL
   */
  async navigate(url: string, waitUntil: string = 'networkidle2'): Promise<void> {
    if (!this.browser) {
      await this.launch();
    }
    
    if (!this.currentPage) {
      this.currentPage = await this.browser.newPage();
    }
    
    console.log(`Navigating to: ${url}`);
    await this.currentPage.goto(url, { waitUntil });
  }
  
  /**
   * Click element
   */
  async click(selector: string): Promise<void> {
    if (!this.currentPage) {
      throw new Error('No active page. Navigate to a URL first.');
    }
    
    await this.currentPage.waitForSelector(selector, { timeout: 10000 });
    await this.currentPage.click(selector);
    console.log(`Clicked: ${selector}`);
  }
  
  /**
   * Type text into input field
   */
  async type(selector: string, text: string, delay: number = 100): Promise<void> {
    if (!this.currentPage) {
      throw new Error('No active page. Navigate to a URL first.');
    }
    
    await this.currentPage.waitForSelector(selector, { timeout: 10000 });
    await this.currentPage.type(selector, text, { delay });
    console.log(`Typed "${text}" into: ${selector}`);
  }
  
  /**
   * Extract text from element
   */
  async getText(selector: string): Promise<string> {
    if (!this.currentPage) {
      throw new Error('No active page. Navigate to a URL first.');
    }
    
    await this.currentPage.waitForSelector(selector, { timeout: 10000 });
    const text = await this.currentPage.$eval(selector, (el: any) => el.textContent);
    return text.trim();
  }
  
  /**
   * Extract multiple elements
   */
  async getElements(selector: string): Promise<any[]> {
    if (!this.currentPage) {
      throw new Error('No active page. Navigate to a URL first.');
    }
    
    return await this.currentPage.$$(selector);
  }
  
  /**
   * Take screenshot
   */
  async screenshot(path: string, fullPage: boolean = false): Promise<void> {
    if (!this.currentPage) {
      throw new Error('No active page. Navigate to a URL first.');
    }
    
    await this.currentPage.screenshot({ path, fullPage });
    console.log(`Screenshot saved: ${path}`);
  }
  
  /**
   * Wait for element
   */
  async waitFor(selector: string, timeout: number = 10000): Promise<void> {
    if (!this.currentPage) {
      throw new Error('No active page. Navigate to a URL first.');
    }
    
    await this.currentPage.waitForSelector(selector, { timeout });
  }
  
  /**
   * Execute JavaScript on page
   */
  async evaluate(script: string | Function): Promise<any> {
    if (!this.currentPage) {
      throw new Error('No active page. Navigate to a URL first.');
    }
    
    return await this.currentPage.evaluate(script);
  }
  
  /**
   * Fill form
   */
  async fillForm(formData: Record<string, string>): Promise<void> {
    for (const [selector, value] of Object.entries(formData)) {
      await this.type(selector, value);
    }
    console.log('Form filled successfully');
  }
  
  /**
   * Extract data from page
   */
  async extractData(selectors: Record<string, string>): Promise<Record<string, string>> {
    const data: Record<string, string> = {};
    
    for (const [key, selector] of Object.entries(selectors)) {
      try {
        data[key] = await this.getText(selector);
      } catch (error) {
        console.error(`Failed to extract ${key}:`, error);
        data[key] = '';
      }
    }
    
    return data;
  }
  
  /**
   * Wait for navigation
   */
  async waitForNavigation(timeout: number = 30000): Promise<void> {
    if (!this.currentPage) {
      throw new Error('No active page.');
    }
    
    await this.currentPage.waitForNavigation({ timeout });
  }
  
  /**
   * Scroll to element
   */
  async scrollTo(selector: string): Promise<void> {
    if (!this.currentPage) {
      throw new Error('No active page.');
    }
    
    await this.currentPage.evaluate((sel: string) => {
      const element = document.querySelector(sel);
      if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }, selector);
  }
  
  /**
   * Get page title
   */
  async getTitle(): Promise<string> {
    if (!this.currentPage) {
      throw new Error('No active page.');
    }
    
    return await this.currentPage.title();
  }
  
  /**
   * Get current URL
   */
  async getUrl(): Promise<string> {
    if (!this.currentPage) {
      throw new Error('No active page.');
    }
    
    return this.currentPage.url();
  }
  
  /**
   * Close current page
   */
  async closePage(): Promise<void> {
    if (this.currentPage) {
      await this.currentPage.close();
      this.currentPage = null;
    }
  }
  
  /**
   * Close browser
   */
  async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.currentPage = null;
      console.log('✓ Browser closed');
    }
  }
}

// Export for Node.js usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PuppeteerController };
}
