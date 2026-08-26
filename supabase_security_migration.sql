-- ====================================================================
-- ARANG COFFEE — ZERO-TRUST SECURITY DEFINER & RPC MIGRATION
-- 1. Unique index on member_transactions(sales_id, type)
-- 2. Parameterless redeem_points(p_reward_id, p_points_cost) with auth.uid()
-- 3. Strict Ownership RLS Policies (auth.uid() = member_id)
-- 4. Revoke add_points & add_stamp from anon/authenticated (VPS Service-Role only)
-- ====================================================================

-- 1. CREATE MEMBER TRANSACTIONS TABLE IF NOT EXISTS
CREATE TABLE IF NOT EXISTS member_transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    member_id UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    sales_id UUID REFERENCES sales(id) ON DELETE SET NULL,
    reward_id UUID REFERENCES rewards(id) ON DELETE SET NULL,
    points_change INT NOT NULL,
    type VARCHAR(50) NOT NULL,
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- HARD UNIQUE CONSTRAINT PREVENTING RACE CONDITION DOUBLE CREDITING
CREATE UNIQUE INDEX IF NOT EXISTS uq_member_tx_sale_type 
ON member_transactions(sales_id, type) 
WHERE sales_id IS NOT NULL;

-- 2. ZERO-TRUST redeem_points (DERIVED FROM auth.uid() DIRECTLY)
CREATE OR REPLACE FUNCTION redeem_points(
    p_reward_id UUID,
    p_points_cost INTEGER
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_member_id UUID := auth.uid(); -- Diperoleh secara selamat daripada JWT session
    v_current_points INTEGER;
    v_reward_name VARCHAR(200);
    v_reward_active BOOLEAN;
    v_reward_limit INTEGER;
    v_redeemed_count INTEGER;
BEGIN
    IF v_member_id IS NULL THEN
        RAISE EXCEPTION 'Sesi tidak sah. Sila log masuk semula.';
    END IF;

    IF p_points_cost IS NULL OR p_points_cost <= 0 THEN
        RAISE EXCEPTION 'Kos mata ganjaran mesti lebih daripada 0';
    END IF;

    SELECT name, is_active, stock_limit, redeemed_count
    INTO v_reward_name, v_reward_active, v_reward_limit, v_redeemed_count
    FROM rewards WHERE id = p_reward_id;

    IF NOT FOUND THEN RAISE EXCEPTION 'Ganjaran tidak dijumpai'; END IF;
    IF NOT v_reward_active THEN RAISE EXCEPTION 'Ganjaran tidak lagi aktif'; END IF;
    IF v_reward_limit > 0 AND v_redeemed_count >= v_reward_limit THEN
        RAISE EXCEPTION 'Ganjaran telah habis ditebus';
    END IF;

    SELECT points INTO v_current_points FROM members WHERE id = v_member_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Profil ahli tidak dijumpai'; END IF;
    IF v_current_points < p_points_cost THEN
        RAISE EXCEPTION 'Mata tidak mencukupi. Baki semasa: % mata, Diperlukan: % mata', v_current_points, p_points_cost;
    END IF;

    INSERT INTO member_transactions (member_id, reward_id, points_change, type, notes)
    VALUES (v_member_id, p_reward_id, -p_points_cost, 'redeem', 'Tebus: ' || v_reward_name);

    UPDATE members SET points = points - p_points_cost, updated_at = NOW() WHERE id = v_member_id;
    UPDATE rewards SET redeemed_count = redeemed_count + 1, updated_at = NOW() WHERE id = p_reward_id;

    RETURN TRUE;
END;
$$;

-- 3. PERMISSIONS: REVOKE STAFF FUNCTIONS FROM CLIENT & GRANT ZERO-TRUST FUNCTIONS
REVOKE INSERT, UPDATE, DELETE ON members FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON member_stamp_cards FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON member_transactions FROM anon, authenticated;

-- Revoke add_points & add_stamp from client roles (POS connects via VPS service-role only)
REVOKE EXECUTE ON FUNCTION add_points(UUID, UUID, INTEGER) FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION add_stamp(UUID, UUID, UUID) FROM anon, authenticated;

-- Grant redeem_points to authenticated users only
GRANT EXECUTE ON FUNCTION redeem_points(UUID, INTEGER) TO authenticated;

-- 4. STRICT OWNERSHIP RLS POLICIES
ALTER TABLE members ENABLE ROW LEVEL SECURITY;
ALTER TABLE member_stamp_cards ENABLE ROW LEVEL SECURITY;
ALTER TABLE member_transactions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow select members" ON members;
DROP POLICY IF EXISTS "Members read own row" ON members;
CREATE POLICY "Members read own row" ON members
    FOR SELECT USING (auth.uid() = id);

DROP POLICY IF EXISTS "Allow select member_stamp_cards" ON member_stamp_cards;
DROP POLICY IF EXISTS "Members read own stamp cards" ON member_stamp_cards;
CREATE POLICY "Members read own stamp cards" ON member_stamp_cards
    FOR SELECT USING (auth.uid() = member_id);

DROP POLICY IF EXISTS "Allow select member_transactions" ON member_transactions;
DROP POLICY IF EXISTS "Members read own transactions" ON member_transactions;
CREATE POLICY "Members read own transactions" ON member_transactions
    FOR SELECT USING (auth.uid() = member_id);
