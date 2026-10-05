import { handleApi } from '../../lib/vercel-api.mjs';

export default function signup(req, res) {
  return handleApi(req, res, 'auth/signup');
}
