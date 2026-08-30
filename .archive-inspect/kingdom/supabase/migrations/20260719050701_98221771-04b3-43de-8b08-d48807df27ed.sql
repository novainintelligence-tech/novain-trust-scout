
CREATE TABLE public.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  target_url TEXT NOT NULL,
  target_host TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'complete',
  duration_ms INTEGER,
  overall_score INTEGER NOT NULL DEFAULT 0,
  scores JSONB NOT NULL DEFAULT '{}'::jsonb,
  headers JSONB NOT NULL DEFAULT '[]'::jsonb,
  cookies JSONB NOT NULL DEFAULT '[]'::jsonb,
  tls JSONB NOT NULL DEFAULT '{}'::jsonb,
  csrf JSONB NOT NULL DEFAULT '[]'::jsonb,
  xss JSONB NOT NULL DEFAULT '[]'::jsonb,
  sessions JSONB NOT NULL DEFAULT '[]'::jsonb,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.scans TO authenticated;
GRANT ALL ON public.scans TO service_role;

ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users manage their own scans"
  ON public.scans FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE INDEX scans_user_created_idx ON public.scans (user_id, created_at DESC);
CREATE INDEX scans_user_host_created_idx ON public.scans (user_id, target_host, created_at DESC);
