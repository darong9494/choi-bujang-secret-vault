-- Stage 10: create one immutable backup row per existing student-owned virtual note.
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;

CREATE TABLE IF NOT EXISTS public.note_backups (
    note_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
    backed_up_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (note_id, owner_id)
);

ALTER TABLE public.note_backups ENABLE ROW LEVEL SECURITY;

INSERT INTO public.note_backups (note_id, owner_id, title, content, content_sha256)
SELECT id, owner_id, title, content, encode(extensions.digest(content, 'sha256'), 'hex')
FROM public.notes
WHERE owner_id IS NOT NULL
ON CONFLICT (note_id, owner_id) DO NOTHING;
