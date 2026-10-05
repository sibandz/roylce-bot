import { handleApi } from '../../lib/vercel-api.mjs';

export default function logout(req, res) {
  return handleApi(req, res, 'auth/logout');
}
