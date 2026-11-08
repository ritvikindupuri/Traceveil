CREATE TABLE public.github_credentials (
 user_id uuid PRIMARY KEY,
 token_ciphertext text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.github_credentials TO service_role;
REVOKE ALL ON public.github_credentials FROM anon, authenticated;
ALTER TABLE public.github_credentials ENABLE ROW LEVEL SECURITY;
COMMENT ON TABLE public.github_credentials IS 'Server-only owner-bound AES-GCM GitHub PATs; no browser grants or policies.';