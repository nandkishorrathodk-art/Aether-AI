import { Router } from 'express';
import { cacheService } from '../services/cache';

export const cacheRoutes = Router();

cacheRoutes.get('/stats', (req, res) => {
  const stats = cacheService.getStats();
  res.json({ success: true, data: stats });
});

cacheRoutes.post('/clear', async (req, res) => {
  await cacheService.clear();
  res.json({ success: true, message: 'Cache cleared' });
});
