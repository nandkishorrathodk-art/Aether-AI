class NotificationService {
  constructor() {
    this.permission = 'default';
    this.requestPermission();
  }

  async requestPermission() {
    if ('Notification' in window) {
      this.permission = await Notification.requestPermission();
    }
  }

  showNotification(title, options = {}) {
    if (!('Notification' in window)) {
      console.warn('Browser does not support notifications');
      return null;
    }

    if (this.permission !== 'granted') {
      console.warn('Notification permission not granted');
      return null;
    }

    const defaultOptions = {
      icon: '/icon_128x128.png',
      badge: '/icon_64x64.png',
      requireInteraction: false,
      ...options,
    };

    try {
      const notification = new Notification(title, defaultOptions);
      return notification;
    } catch (error) {
      console.error('Failed to show notification:', error);
      return null;
    }
  }

  showProactiveSuggestion(suggestion) {
    return this.showNotification('Aether AI - New Suggestion', {
      body: suggestion.description || suggestion.title,
      icon: '/icon_128x128.png',
      tag: `suggestion-${suggestion.id}`,
      requireInteraction: true,
      data: suggestion,
    });
  }

  showBugFound(bug) {
    return this.showNotification('Aether AI - Bug Found! 🐛', {
      body: `${bug.title} - Severity: ${bug.severity}`,
      icon: '/icon_128x128.png',
      tag: `bug-${bug.id}`,
      requireInteraction: true,
      data: bug,
    });
  }

  showDailyReminder(message) {
    return this.showNotification('Aether AI - Daily Reminder 📅', {
      body: message,
      icon: '/icon_128x128.png',
      tag: 'daily-reminder',
      requireInteraction: false,
    });
  }

  showMotivation(message) {
    return this.showNotification('Aether AI - Motivation 💪', {
      body: message,
      icon: '/icon_128x128.png',
      tag: 'motivation',
      requireInteraction: false,
    });
  }

  showBreakReminder() {
    return this.showNotification('Aether AI - Time for a Break ☕', {
      body: 'Boss! Thoda break le lo. Aapki ankhon ko rest chahiye! 😊',
      icon: '/icon_128x128.png',
      tag: 'break-reminder',
      requireInteraction: false,
    });
  }

  async testNotification() {
    await this.requestPermission();
    return this.showNotification('Aether AI - Test Notification', {
      body: 'Ji boss! Notifications kaam kar rahe hain! 🎉',
    });
  }
}

export default new NotificationService();
