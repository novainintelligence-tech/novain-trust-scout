DROP POLICY IF EXISTS "Users manage their own scans" ON public.scans;

CREATE POLICY "Users read their own scans" ON public.scans
  FOR SELECT TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Editors insert their own scans" ON public.scans
  FOR INSERT TO authenticated
  WITH CHECK (
    auth.uid() = user_id
    AND (public.has_role(auth.uid(), 'admin') OR public.has_role(auth.uid(), 'editor'))
  );

CREATE POLICY "Editors update their own scans" ON public.scans
  FOR UPDATE TO authenticated
  USING (
    auth.uid() = user_id
    AND (public.has_role(auth.uid(), 'admin') OR public.has_role(auth.uid(), 'editor'))
  )
  WITH CHECK (
    auth.uid() = user_id
    AND (public.has_role(auth.uid(), 'admin') OR public.has_role(auth.uid(), 'editor'))
  );

CREATE POLICY "Editors delete their own scans" ON public.scans
  FOR DELETE TO authenticated
  USING (
    auth.uid() = user_id
    AND (public.has_role(auth.uid(), 'admin') OR public.has_role(auth.uid(), 'editor'))
  );
