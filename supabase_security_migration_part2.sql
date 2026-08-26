-- ====================================================================
-- ARANG COFFEE — SECURITY MIGRATION PART 2
-- Menutup lubang RLS yang masih terbuka selepas migration pertama:
--   pos_staff, pos_settings, pos_payroll, promotions, lucky_codes
-- Juga menambah claim_lucky_code() zero-trust RPC (guna auth.uid()).
--
-- CATATAN PENTING:
-- server.js menyambung ke Supabase guna SERVICE_ROLE_KEY, jadi RLS di
-- bawah ini TIDAK menyekat server.js sendiri (service-role bypass RLS
-- secara rekabentuk). Migration ini hanya menutup laluan serangan
-- "browser terus ke Supabase" (guna anon key / customer JWT).
-- Laluan "browser terus ke server.js API" mesti dibetulkan berasingan
-- di peringkat aplikasi — lihat gemini_fix_prompt_server_auth.md
-- ====================================================================

-- ------------------------------------------------------------------
-- 1. pos_staff — buang akses baca/tulis awam. Staff PIN TIDAK BOLEH
--    dibaca oleh anon/authenticated langsung. Hanya service-role
--    (server.js) boleh access jadual ini.
-- ------------------------------------------------------------------
DROP POLICY IF EXISTS "Allow public read access to pos_staff" ON pos_staff;
DROP POLICY IF EXISTS "Allow authenticated full access to pos_staff" ON pos_staff;

ALTER TABLE pos_staff ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS pos_staff ALTER COLUMN pin TYPE TEXT;
-- Tiada policy langsung ditambah untuk anon/authenticated = default deny.
-- Service-role (server.js) tetap boleh access sebab service-role bypass RLS.

REVOKE ALL ON pos_staff FROM anon, authenticated;

-- ------------------------------------------------------------------
-- 2. pos_payroll — data gaji staf. Deny semua akses client-side.
-- ------------------------------------------------------------------
DROP POLICY IF EXISTS "Allow public read access to pos_payroll" ON pos_payroll;
DROP POLICY IF EXISTS "Allow authenticated full access to pos_payroll" ON pos_payroll;

ALTER TABLE pos_payroll ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON pos_payroll FROM anon, authenticated;

-- ------------------------------------------------------------------
-- 3. pos_settings — settings admin (lucky draw gifts/claims, rewards
--    settings, printer, e-invoice). Deny semua akses client-side;
--    hanya boleh dibaca/ditulis oleh service-role (server.js).
--    Jika ada bahagian yang MEMANG perlu dibaca terus oleh customer
--    (cth. senarai hadiah aktif untuk paparan), buat jadual/view
--    berasingan yang public-safe (lihat #6) — jangan biarkan
--    pos_settings sendiri terbuka.
-- ------------------------------------------------------------------
DROP POLICY IF EXISTS "Allow public read access to pos_settings" ON pos_settings;
DROP POLICY IF EXISTS "Allow authenticated full access to pos_settings" ON pos_settings;

ALTER TABLE pos_settings ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON pos_settings FROM anon, authenticated;

-- ------------------------------------------------------------------
-- 4. promotions — sebelum ini FOR ALL USING(true) WITH CHECK(true),
--    iaitu sesiapa (termasuk tanpa login) boleh insert/update/delete.
--    Baca terus dibenarkan (memang untuk paparan awam), tapi tulis
--    hanya melalui service-role.
-- ------------------------------------------------------------------
DROP POLICY IF EXISTS "Allow manage promotions" ON promotions;
DROP POLICY IF EXISTS "Allow select promotions" ON promotions;

CREATE POLICY "Public read promotions" ON promotions
    FOR SELECT USING (true);
-- Tiada policy INSERT/UPDATE/DELETE untuk anon/authenticated = default deny.
REVOKE INSERT, UPDATE, DELETE ON promotions FROM anon, authenticated;

-- ------------------------------------------------------------------
-- 5. lucky_codes — kunci ketat. Ahli hanya boleh baca kod milik dia
--    sendiri (selepas ditebus). Tulis (mark is_used, assign member_id)
--    hanya melalui RPC claim_lucky_code() di bawah, bukan UPDATE terus.
-- ------------------------------------------------------------------
ALTER TABLE lucky_codes ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow select lucky_codes" ON lucky_codes;
DROP POLICY IF EXISTS "Members read own lucky codes" ON lucky_codes;
CREATE POLICY "Members read own lucky codes" ON lucky_codes
    FOR SELECT USING (auth.uid() = member_id);

REVOKE INSERT, UPDATE, DELETE ON lucky_codes FROM anon, authenticated;

-- ------------------------------------------------------------------
-- 6. claim_lucky_code() — zero-trust RPC, member_id diambil dari
--    auth.uid() (session sebenar), BUKAN daripada parameter yang
--    boleh dipalsukan oleh client. Gantikan logik custom di
--    server.js /api/loyalty/lucky-draw/enter dengan panggilan RPC ini.
-- ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION claim_lucky_code(
    p_code VARCHAR(30)
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_member_id UUID := auth.uid();
    v_code_record RECORD;
BEGIN
    IF v_member_id IS NULL THEN
        RAISE EXCEPTION 'Sesi tidak sah. Sila log masuk semula.';
    END IF;

    SELECT * INTO v_code_record FROM lucky_codes
    WHERE lower(code) = lower(p_code)
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Kod cabutan bertuah tidak sah atau tidak wujud';
    END IF;

    IF NOT v_code_record.is_printed THEN
        RAISE EXCEPTION 'Kod belum sah/belum dikeluarkan pada resit';
    END IF;

    IF v_code_record.is_used THEN
        RAISE EXCEPTION 'Kod cabutan bertuah ini telah pun ditebus pada %', v_code_record.used_at;
    END IF;

    UPDATE lucky_codes
    SET is_used = TRUE,
        member_id = v_member_id,
        used_at = NOW()
    WHERE id = v_code_record.id;

    RETURN jsonb_build_object(
        'success', TRUE,
        'prize_name', COALESCE(v_code_record.prize_name, NULL),
        'code', v_code_record.code,
        'claimed_at', NOW()
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION claim_lucky_code(VARCHAR) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_lucky_code(VARCHAR) TO authenticated;
