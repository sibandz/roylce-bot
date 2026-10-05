import { handleApi } from '../../lib/vercel-api.mjs';

export default function me(req, res) {
  return handleApi(req, res, 'auth/me');
}
