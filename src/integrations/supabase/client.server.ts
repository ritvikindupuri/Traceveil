import { createServerDbClient } from '@/lib/server/db.server';

// Server-side database client for administrative and background operations.
// No Supabase external credentials required.
export const supabaseAdmin = createServerDbClient();
