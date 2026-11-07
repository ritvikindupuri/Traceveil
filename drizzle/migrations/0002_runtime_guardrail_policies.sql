CREATE TABLE public.guardrail_policies (
 user_id uuid PRIMARY KEY,
 policy jsonb NOT NULL,
 revision uuid NOT NULL DEFAULT gen_random_uuid(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON public.guardrail_policies TO authenticated;
GRANT ALL ON public.guardrail_policies TO service_role;
ALTER TABLE public.guardrail_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Owners read runtime policy" ON public.guardrail_policies FOR SELECT TO authenticated USING (auth.uid() = user_id);