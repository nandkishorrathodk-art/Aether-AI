const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electron', {
  send: (channel, data) => {
    const validChannels = ['minimize-window', 'close-window', 'maximize-window', 'minimize-to-tray', 'show-window'];
    if (validChannels.includes(channel)) {
      ipcRenderer.send(channel, data);
    }
  },
  ipcRenderer: {
    send: (channel, data) => {
      const validChannels = ['minimize-window', 'close-window', 'maximize-window', 'minimize-to-tray', 'show-window'];
      if (validChannels.includes(channel)) {
        ipcRenderer.send(channel, data);
      }
    },
    on: (channel, func) => {
      const validChannels = ['toggle-voice-input', 'activate-voice-input', 'show-notification'];
      if (validChannels.includes(channel)) {
        ipcRenderer.on(channel, (event, ...args) => func(...args));
      }
    },
    removeListener: (channel, func) => {
      const validChannels = ['toggle-voice-input', 'activate-voice-input', 'show-notification'];
      if (validChannels.includes(channel)) {
        ipcRenderer.removeListener(channel, func);
      }
    },
    invoke: async (channel, ...args) => {
      const validChannels = ['get-store-value', 'set-store-value', 'set-auto-launch', 'show-notification'];
      if (validChannels.includes(channel)) {
        return await ipcRenderer.invoke(channel, ...args);
      }
    }
  }
});
