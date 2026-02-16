import { Router } from 'express';

export const fileRoutes = Router();

fileRoutes.get('/status', (req, res) => {
  res.json({ success: true, message: 'File routes active' });
});
