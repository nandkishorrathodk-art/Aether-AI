import { Router } from 'express';

export const realtimeRoutes = Router();

realtimeRoutes.get('/status', (req, res) => {
  res.json({ success: true, message: 'Real-time routes active' });
});
