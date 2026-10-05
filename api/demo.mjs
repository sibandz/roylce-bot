import { handleApi } from '../lib/vercel-api.mjs';

export default function demo(req, res) {
  return handleApi(req, res, 'demo');
}
