import { handleApi } from '../lib/vercel-api.mjs';

export default function health(req, res) {
  return handleApi(req, res, 'health');
}
