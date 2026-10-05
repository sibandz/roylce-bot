import { handleApi } from '../../lib/vercel-api.mjs';

export default function login(req, res) {
  return handleApi(req, res, 'auth/login');
}
