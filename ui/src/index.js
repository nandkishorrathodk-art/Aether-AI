import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import VoiceApp from './VoiceApp';  // Voice-only mode!

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <VoiceApp />
  </React.StrictMode>
);
