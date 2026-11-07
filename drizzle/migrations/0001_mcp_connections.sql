CREATE TABLE public.mcp_connections (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL, name text NOT NULL, endpoint text NOT NULL, enabled boolean NOT NULL DEFAULT true, token_ciphertext text, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(user_id, endpoint));
GRANT ALL ON public.mcp_connections TO service_role;
ALTER TABLE public.mcp_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_records ADD COLUMN connection_id uuid REFERENCES public.mcp_connections(id) ON DELETE SET NULL;