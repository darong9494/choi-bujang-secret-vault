-- 1. Create notes table with owner_id column (without auth.users foreign key constraint)
CREATE TABLE IF NOT EXISTS public.notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    owner_id UUID NULL
);

-- 2. Enable Row Level Security (RLS)
ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;

-- 3. Explicitly ensure anon and authenticated roles have NO select permissions by default under RLS.
-- (By enabling RLS without adding SELECT policies for anon/authenticated, all queries from these roles are blocked)

-- 4. Insert initial 3 mock notes
INSERT INTO public.notes (title, content, owner_id)
VALUES
    ('Secret Vault Setup Notice', 'This is a initial sample note stored in database for learning purposes.', '00000000-0000-0000-0000-000000000000'),
    ('Security Drill Reminder', 'Always verify RLS policies and server-side API permissions before production.', '00000000-0000-0000-0000-000000000000'),
    ('System Maintenance', 'Ensure static data.json contains no actual note data.', '00000000-0000-0000-0000-000000000000');