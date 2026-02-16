import React, { useState, useEffect } from 'react';
import { Snackbar, Alert, IconButton } from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';

function Notifications() {
  const [notifications, setNotifications] = useState([]);

  useEffect(() => {
    const handleNotification = (data) => {
      const notification = {
        id: Date.now(),
        title: data.title,
        body: data.body,
        severity: data.severity || 'info',
        timestamp: new Date(),
      };

      setNotifications((prev) => [...prev, notification]);

      setTimeout(() => {
        removeNotification(notification.id);
      }, 5000);
    };

    window.electron?.ipcRenderer.on('show-notification', handleNotification);

    return () => {
      window.electron?.ipcRenderer.removeListener('show-notification', handleNotification);
    };
  }, []);

  const removeNotification = (id) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  };

  return (
    <>
      {notifications.map((notification, index) => (
        <Snackbar
          key={notification.id}
          open={true}
          anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
          sx={{ top: { xs: 16 + index * 70, sm: 24 + index * 70 } }}
        >
          <Alert
            severity={notification.severity}
            action={
              <IconButton
                size="small"
                aria-label="close"
                color="inherit"
                onClick={() => removeNotification(notification.id)}
              >
                <CloseIcon fontSize="small" />
              </IconButton>
            }
            sx={{ width: '100%' }}
          >
            {notification.title && <strong>{notification.title}: </strong>}
            {notification.body}
          </Alert>
        </Snackbar>
      ))}
    </>
  );
}

export default Notifications;
