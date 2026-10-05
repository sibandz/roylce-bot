import { createCloudAdmin, createCloudInvite } from '../lib/vercel-api.mjs';

const [command, ...args] = process.argv.slice(2);

try {
  if (command === 'admin') {
    const username = args[0] || 'admin';
    const password = await createCloudAdmin(username);
    console.log(`Rolyce Pilot administrator created.\nUsername: ${username}\nTemporary password (shown once): ${password}\nSave this password in a password manager.`);
  } else if (command === 'invite') {
    const label = args.join(' ').trim() || 'standard';
    const code = await createCloudInvite(label);
    console.log(`One-time Rolyce Pilot signup code (${label}; expires in 30 days):\n${code}\nGive this code to the invited user. It will only be shown once.`);
  } else {
    throw new Error('Use "admin [username]" or "invite [label]".');
  }
} catch (error) {
  console.error(`Cloud account command failed: ${error.message}`);
  process.exitCode = 1;
}
