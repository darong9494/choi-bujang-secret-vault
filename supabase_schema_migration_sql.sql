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

-- 4. Insert the four virtual notes shown in the sample UI
INSERT INTO public.notes (title, content, owner_id)
VALUES
    ('과제', '실습용 가상 과제 기록', '00000000-0000-0000-0000-000000000000'),
    ('포트폴리오', '실습용 가상 포트폴리오 기록', '00000000-0000-0000-0000-000000000000'),
    ('아침 리추얼', '실습용 가상 리추얼 기록', '00000000-0000-0000-0000-000000000000'),
    ('훈련 행정 자료', '실습용 가상 행정 기록', '00000000-0000-0000-0000-000000000000');
