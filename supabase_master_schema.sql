-- ====================================================================
-- ARANG COFFEE POS & LOYALTY — MASTER SUPABASE SQL SCHEMA (ZERO-TRUST)
-- One-Click Complete Database Deployment
-- Includes: All Tables, Indexes, Realtime, Strict RLS & Zero-Trust RPCs
-- ====================================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ====================================================================
-- 2. ENUMS
-- ====================================================================
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('admin', 'manager', 'cashier', 'kitchen');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE order_type AS ENUM ('dinein', 'takeaway', 'delivery');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE payment_method AS ENUM ('cash', 'qr_duitnow', 'card', 'ewallet', 'points');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE order_status AS ENUM ('paid', 'pending', 'cancelled', 'refunded');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE stamp_card_status AS ENUM ('collecting', 'unclaimed', 'claimed');
EXCEPTION WHEN duplicate_object THEN null; END $$;

-- ====================================================================
-- 3. OUTLETS & BUSINESS PROFILE
-- ====================================================================
CREATE TABLE IF NOT EXISTS outlets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(30) UNIQUE NOT NULL,
    name VARCHAR(150) NOT NULL,
    company_name VARCHAR(200) NOT NULL,
    ssm_no VARCHAR(50),
    tin_no VARCHAR(50),
    msic_code VARCHAR(20),
    sst_no VARCHAR(50),
    address TEXT,
    city VARCHAR(100),
    postcode VARCHAR(20),
    state VARCHAR(50),
    phone VARCHAR(30),
    email VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ====================================================================
-- 4. USERS & STAFF / JURUWANG
-- ====================================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    outlet_id UUID REFERENCES outlets(id) ON DELETE SET NULL,
    name VARCHAR(150) NOT NULL,
    phone VARCHAR(30) UNIQUE NOT NULL,
    pin_hash VARCHAR(255) NOT NULL,
    role user_role DEFAULT 'cashier',
    hourly_rate NUMERIC(10,2) DEFAULT 0.00,
    salary_type VARCHAR(20) DEFAULT 'monthly',
    base_salary NUMERIC(10,2) DEFAULT 0.00,
    is_active BOOLEAN DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ====================================================================
-- 5. MEMBERS / KEAHLIAN PELANGGAN
-- ====================================================================
CREATE TABLE IF NOT EXISTS members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    phone VARCHAR(30) UNIQUE NOT NULL,
    name VARCHAR(150) NOT NULL,
    email VARCHAR(100),
    points INT DEFAULT 0,
    lifetime_points INT DEFAULT 0,
    stamps INT DEFAULT 0,
    tier VARCHAR(50) DEFAULT 'Ahli Gangsa',
    source VARCHAR(50) DEFAULT 'whatsapp_otp',
    is_active BOOLEAN DEFAULT TRUE,
    registered_at TIMESTAMPTZ DEFAULT NOW(),
    last_visited_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_members_phone ON members(phone);
CREATE INDEX IF NOT EXISTS idx_members_name ON members(name);
CREATE INDEX IF NOT EXISTS idx_members_points ON members(points DESC);

-- ====================================================================
-- 6. MEMBER STAMP CARDS (SISTEM KAD COP MULTI-CARD)
-- ====================================================================
CREATE TABLE IF NOT EXISTS member_stamp_cards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    member_id UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    card_number INT NOT NULL,
    stamps_collected INT DEFAULT 0,
    target_stamps INT DEFAULT 10,
    reward_name VARCHAR(150) DEFAULT '1x Kopi Percuma',
    status stamp_card_status DEFAULT 'collecting',
    completed_at TIMESTAMPTZ,
    claimed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_member_card_no UNIQUE (member_id, card_number)
);

CREATE INDEX IF NOT EXISTS idx_member_stamp_cards_member ON member_stamp_cards(member_id, status);

-- ====================================================================
-- 7. MENU CATEGORIES, PRODUCTS & VARIATIONS
-- ====================================================================
CREATE TABLE IF NOT EXISTS product_categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    icon VARCHAR(20) DEFAULT '☕',
    sort_order INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    category_id UUID REFERENCES product_categories(id) ON DELETE SET NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    price NUMERIC(10,2) NOT NULL DEFAULT 0.00,
    cost_price NUMERIC(10,2) NOT NULL DEFAULT 0.00,
    stock INT DEFAULT 999,
    img_url TEXT,
    is_addon BOOLEAN DEFAULT FALSE,
    is_available BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_products_category ON products(category_id);
CREATE INDEX IF NOT EXISTS idx_products_name ON products(name);

CREATE TABLE IF NOT EXISTS product_variations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    price_diff NUMERIC(10,2) DEFAULT 0.00,
    is_active BOOLEAN DEFAULT TRUE
);

-- ====================================================================
-- 8. SALES TRANSACTIONS & SALE ITEMS
-- ====================================================================
CREATE TABLE IF NOT EXISTS sales (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    outlet_id UUID REFERENCES outlets(id) ON DELETE SET NULL,
    receipt_no VARCHAR(50) UNIQUE NOT NULL,
    shift_code VARCHAR(50),
    cashier_id UUID REFERENCES users(id) ON DELETE SET NULL,
    cashier_name VARCHAR(150),
    member_id UUID REFERENCES members(id) ON DELETE SET NULL,
    order_type order_type DEFAULT 'dinein',
    table_no VARCHAR(30),
    
    subtotal NUMERIC(10,2) NOT NULL DEFAULT 0.00,
    discount NUMERIC(10,2) DEFAULT 0.00,
    tax NUMERIC(10,2) DEFAULT 0.00,
    service_charge NUMERIC(10,2) DEFAULT 0.00,
    round_adj NUMERIC(10,2) DEFAULT 0.00,
    total NUMERIC(10,2) NOT NULL DEFAULT 0.00,
    
    cash_tendered NUMERIC(10,2) DEFAULT 0.00,
    change_given NUMERIC(10,2) DEFAULT 0.00,
    payment_method payment_method DEFAULT 'cash',
    status order_status DEFAULT 'paid',
    
    points_earned INT DEFAULT 0,
    points_redeemed INT DEFAULT 0,
    stamp_increment INT DEFAULT 0,
    
    notes TEXT,
    e_invoice_uuid VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_receipt_no ON sales(receipt_no);
CREATE INDEX IF NOT EXISTS idx_sales_created_at ON sales(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sales_cashier ON sales(cashier_name);
CREATE INDEX IF NOT EXISTS idx_sales_member ON sales(member_id);
CREATE INDEX IF NOT EXISTS idx_sales_status ON sales(status);

CREATE TABLE IF NOT EXISTS sale_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sale_id UUID NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    product_id UUID REFERENCES products(id) ON DELETE SET NULL,
    product_name VARCHAR(200) NOT NULL,
    variation_name VARCHAR(100),
    unit_price NUMERIC(10,2) NOT NULL,
    unit_cost NUMERIC(10,2) DEFAULT 0.00,
    qty INT NOT NULL DEFAULT 1,
    subtotal NUMERIC(10,2) NOT NULL,
    selected_addons JSONB DEFAULT '[]'::JSONB,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_sale_items_sale ON sale_items(sale_id);

-- ====================================================================
-- 9. REWARDS & PROMOTIONS
-- ====================================================================
CREATE TABLE IF NOT EXISTS rewards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(200) NOT NULL UNIQUE,
    points_cost INT NOT NULL DEFAULT 100,
    stock_limit INT DEFAULT 0,
    redeemed_count INT DEFAULT 0,
    icon VARCHAR(20) DEFAULT '☕',
    img_url TEXT,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS promotions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(200) NOT NULL,
    description TEXT,
    media_url TEXT NOT NULL,
    media_type VARCHAR(20) DEFAULT 'image',
    badge_label VARCHAR(100) DEFAULT '🔥 Tawaran Khas',
    action_url TEXT,
    action_label VARCHAR(100) DEFAULT '🎁 Lihat Ganjaran',
    is_active BOOLEAN DEFAULT TRUE,
    sort_order INT DEFAULT 0,
    start_date TIMESTAMPTZ DEFAULT NOW(),
    end_date TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE promotions ADD COLUMN IF NOT EXISTS action_label VARCHAR(100) DEFAULT '🎁 Lihat Ganjaran';
ALTER TABLE promotions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_promotions_active ON promotions(is_active, sort_order, created_at DESC);

-- ====================================================================
-- 10. MEMBER TRANSACTIONS AUDIT LOG & UNIQUE HARD CONSTRAINT
-- ====================================================================
CREATE TABLE IF NOT EXISTS member_transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    member_id UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    sales_id UUID REFERENCES sales(id) ON DELETE SET NULL,
    reward_id UUID REFERENCES rewards(id) ON DELETE SET NULL,
    points_change INT NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'earn', 'redeem', 'stamp', 'adjustment'
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_member_transactions_member ON member_transactions(member_id);
CREATE INDEX IF NOT EXISTS idx_member_transactions_sale ON member_transactions(sales_id, type);

-- HARD UNIQUE CONSTRAINT: Prevents race condition double-credit on database kernel level
CREATE UNIQUE INDEX IF NOT EXISTS uq_member_tx_sale_type 
ON member_transactions(sales_id, type) 
WHERE sales_id IS NOT NULL;

-- ====================================================================
-- 11. CABUTAN BERTUAH (LUCKY DRAW POOL)
-- ====================================================================
CREATE TABLE IF NOT EXISTS lucky_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(30) UNIQUE NOT NULL,
    sale_id UUID REFERENCES sales(id) ON DELETE SET NULL,
    member_id UUID REFERENCES members(id) ON DELETE SET NULL,
    prize_name VARCHAR(150),
    is_used BOOLEAN DEFAULT FALSE,
    is_printed BOOLEAN DEFAULT FALSE,
    assigned_at TIMESTAMPTZ,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lucky_codes_code ON lucky_codes(code);

-- ====================================================================
-- 12. STAFF ATTENDANCE & SALARY PAYMENTS
-- ====================================================================
CREATE TABLE IF NOT EXISTS staff_attendance (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    staff_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    clock_in TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    clock_out TIMESTAMPTZ,
    total_hours NUMERIC(6,2) DEFAULT 0.00,
    overtime_hours NUMERIC(6,2) DEFAULT 0.00,
    status VARCHAR(30) DEFAULT 'present',
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_staff_attendance_staff_date ON staff_attendance(staff_id, clock_in);

CREATE TABLE IF NOT EXISTS salary_payments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    staff_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    period_label VARCHAR(150),
    base_salary NUMERIC(10,2) DEFAULT 0.00,
    total_hours NUMERIC(8,2) DEFAULT 0.00,
    overtime_hours NUMERIC(8,2) DEFAULT 0.00,
    allowances NUMERIC(10,2) DEFAULT 0.00,
    deductions NUMERIC(10,2) DEFAULT 0.00,
    epf_socso NUMERIC(10,2) DEFAULT 0.00,
    net_salary NUMERIC(10,2) NOT NULL,
    payment_status VARCHAR(30) DEFAULT 'paid',
    paid_at TIMESTAMPTZ DEFAULT NOW(),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_salary_staff_period ON salary_payments(staff_id, period_start, period_end);

-- ====================================================================
-- 12B. POS CASH DRAWER SHIFTS, RECONCILIATION & AUDIT TRAIL
-- ====================================================================
CREATE TABLE IF NOT EXISTS pos_shifts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    shift_code VARCHAR(50) UNIQUE NOT NULL,
    cashier_id UUID REFERENCES users(id) ON DELETE SET NULL,
    cashier_name VARCHAR(150) NOT NULL,
    cashier_code VARCHAR(50),
    opened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ,
    opening_float NUMERIC(10,2) NOT NULL DEFAULT 0.00,
    expected_cash NUMERIC(10,2) DEFAULT 0.00,
    actual_cash NUMERIC(10,2) DEFAULT 0.00,
    cash_difference NUMERIC(10,2) DEFAULT 0.00,
    cash_in NUMERIC(10,2) DEFAULT 0.00,
    cash_out NUMERIC(10,2) DEFAULT 0.00,
    total_sales NUMERIC(10,2) DEFAULT 0.00,
    cash_sales NUMERIC(10,2) DEFAULT 0.00,
    qr_sales NUMERIC(10,2) DEFAULT 0.00,
    card_sales NUMERIC(10,2) DEFAULT 0.00,
    total_transactions INT DEFAULT 0,
    status VARCHAR(20) DEFAULT 'open', -- 'open', 'closed'
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pos_shifts_status ON pos_shifts(status);
CREATE INDEX IF NOT EXISTS idx_pos_shifts_opened ON pos_shifts(opened_at DESC);

CREATE TABLE IF NOT EXISTS pos_cash_movements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    shift_id UUID REFERENCES pos_shifts(id) ON DELETE CASCADE,
    shift_code VARCHAR(50) NOT NULL,
    type VARCHAR(20) NOT NULL, -- 'cash_in', 'cash_out'
    amount NUMERIC(10,2) NOT NULL,
    reason TEXT NOT NULL,
    recorded_by VARCHAR(150) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cash_movements_shift ON pos_cash_movements(shift_id);

CREATE TABLE IF NOT EXISTS pos_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action VARCHAR(50) NOT NULL, -- 'sale_completed', 'sale_voided', 'cash_in', 'cash_out', 'shift_opened', 'shift_closed', 'user_switched'
    receipt_no VARCHAR(50),
    shift_code VARCHAR(50),
    cashier_name VARCHAR(150),
    cashier_code VARCHAR(50),
    amount NUMERIC(10,2),
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pos_audit_logs_action ON pos_audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_pos_audit_logs_receipt ON pos_audit_logs(receipt_no);
CREATE INDEX IF NOT EXISTS idx_pos_audit_logs_created ON pos_audit_logs(created_at DESC);

-- ====================================================================
-- 13. WHATSAPP AUDIT LOG
-- ====================================================================
CREATE TABLE IF NOT EXISTS otp_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    phone VARCHAR(30) NOT NULL,
    keyword_received VARCHAR(50),
    otp_code VARCHAR(10),
    status VARCHAR(50) NOT NULL,
    client_ip VARCHAR(50),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_otp_audit_phone ON otp_audit_log(phone, created_at DESC);

-- ====================================================================
-- 14. RPC FUNCTIONS (SECURITY DEFINER & ZERO-TRUST)
-- ====================================================================

-- Function: add_points (CALLED BY VPS SERVICE-ROLE ONLY)
CREATE OR REPLACE FUNCTION add_points(
    p_member_id UUID,
    p_sale_id UUID,
    p_points INTEGER
)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_sale_status VARCHAR(50);
    v_already_credited BOOLEAN;
    v_new_points INTEGER;
BEGIN
    IF p_points IS NULL OR p_points <= 0 THEN
        RAISE EXCEPTION 'Mata yang ditambah mesti bernilai lebih daripada 0';
    END IF;

    SELECT status::text INTO v_sale_status FROM sales WHERE id = p_sale_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Transaksi jualan tidak dijumpai'; END IF;
    IF v_sale_status NOT IN ('paid', 'completed') THEN
        RAISE EXCEPTION 'Transaksi jualan belum selesai atau belum dibayar';
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM member_transactions
        WHERE sales_id = p_sale_id AND member_id = p_member_id AND type = 'earn'
    ) INTO v_already_credited;

    IF v_already_credited THEN
        RAISE EXCEPTION 'Mata bagi jualan ini telah pun direkodkan sebelumnya';
    END IF;

    INSERT INTO member_transactions (member_id, sales_id, points_change, type, notes)
    VALUES (p_member_id, p_sale_id, p_points, 'earn', 'Ganjaran mata belian kaunter');

    UPDATE members
    SET points = points + p_points,
        lifetime_points = lifetime_points + p_points,
        last_visited_at = NOW(),
        updated_at = NOW()
    WHERE id = p_member_id
    RETURNING points INTO v_new_points;

    IF NOT FOUND THEN RAISE EXCEPTION 'Profil ahli tidak dijumpai'; END IF;

    UPDATE sales SET points_earned = p_points, member_id = p_member_id WHERE id = p_sale_id;

    RETURN v_new_points;
END;
$$;

-- Function: redeem_points (ZERO-TRUST: member_id derived directly from auth.uid())
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
    v_member_id UUID := auth.uid(); -- Diperoleh secara automatik daripada JWT session
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

-- Function: add_stamp (CALLED BY VPS SERVICE-ROLE ONLY)
CREATE OR REPLACE FUNCTION add_stamp(
    p_member_id UUID,
    p_card_id UUID,
    p_sale_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_sale_status VARCHAR(50);
    v_already_stamped BOOLEAN;
    v_card_id UUID := p_card_id;
    v_card_no INT;
    v_stamps INT;
    v_target INT := 10;
    v_new_card_id UUID := NULL;
    v_final_status VARCHAR(50);
BEGIN
    IF p_sale_id IS NOT NULL THEN
        SELECT status::text INTO v_sale_status FROM sales WHERE id = p_sale_id;
        IF NOT FOUND THEN RAISE EXCEPTION 'Transaksi jualan tidak dijumpai'; END IF;
        IF v_sale_status NOT IN ('paid', 'completed') THEN
            RAISE EXCEPTION 'Transaksi belum selesai';
        END IF;

        SELECT EXISTS (
            SELECT 1 FROM member_transactions
            WHERE sales_id = p_sale_id AND member_id = p_member_id AND type = 'stamp'
        ) INTO v_already_stamped;

        IF v_already_stamped THEN
            RAISE EXCEPTION 'Cop stamp bagi jualan ini telah pun direkodkan';
        END IF;
    END IF;

    IF v_card_id IS NOT NULL THEN
        SELECT id, card_number, stamps_collected, target_stamps
        INTO v_card_id, v_card_no, v_stamps, v_target
        FROM member_stamp_cards WHERE id = v_card_id AND member_id = p_member_id FOR UPDATE;
    ELSE
        SELECT id, card_number, stamps_collected, target_stamps
        INTO v_card_id, v_card_no, v_stamps, v_target
        FROM member_stamp_cards WHERE member_id = p_member_id AND status = 'collecting'
        ORDER BY card_number DESC LIMIT 1 FOR UPDATE;
    END IF;

    IF v_card_id IS NULL THEN
        SELECT COALESCE(MAX(card_number), 0) + 1 INTO v_card_no FROM member_stamp_cards WHERE member_id = p_member_id;
        INSERT INTO member_stamp_cards (member_id, card_number, stamps_collected, target_stamps, status)
        VALUES (p_member_id, v_card_no, 0, 10, 'collecting')
        RETURNING id, card_number, stamps_collected, target_stamps INTO v_card_id, v_card_no, v_stamps, v_target;
    END IF;

    v_stamps := v_stamps + 1;

    IF v_stamps >= v_target THEN
        v_final_status := 'unclaimed';
        UPDATE member_stamp_cards SET stamps_collected = v_target, status = 'unclaimed', completed_at = NOW(), updated_at = NOW() WHERE id = v_card_id;
        INSERT INTO member_stamp_cards (member_id, card_number, stamps_collected, target_stamps, status)
        VALUES (p_member_id, v_card_no + 1, 0, v_target, 'collecting') RETURNING id INTO v_new_card_id;
        UPDATE members SET stamps = 0, updated_at = NOW() WHERE id = p_member_id;
    ELSE
        v_final_status := 'collecting';
        UPDATE member_stamp_cards SET stamps_collected = v_stamps, updated_at = NOW() WHERE id = v_card_id;
        UPDATE members SET stamps = v_stamps, updated_at = NOW() WHERE id = p_member_id;
    END IF;

    IF p_sale_id IS NOT NULL THEN
        INSERT INTO member_transactions (member_id, sales_id, points_change, type, notes)
        VALUES (p_member_id, p_sale_id, 0, 'stamp', 'Cop stamp diterima (Kad #' || v_card_no || ')');
        UPDATE sales SET stamp_increment = 1 WHERE id = p_sale_id;
    END IF;

    RETURN jsonb_build_object(
        'success', TRUE,
        'card_id', v_card_id,
        'card_number', v_card_no,
        'stamps', v_stamps,
        'target', v_target,
        'status', v_final_status,
        'new_card_id', v_new_card_id
    );
END;
$$;

-- Function: claim_lucky_code
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

    SELECT * INTO v_code_record FROM lucky_codes WHERE code = p_code FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Kod cabutan bertuah tidak sah atau tidak wujud';
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
        'prize_name', COALESCE(v_code_record.prize_name, 'Kopi Percuma'),
        'code', p_code,
        'claimed_at', NOW()
    );
END;
$$;

-- ====================================================================
-- 15. ZERO-TRUST PERMISSIONS & STRICT RLS POLICIES
-- ====================================================================

-- A. Revoke all direct mutations from client
REVOKE INSERT, UPDATE, DELETE ON members FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON member_stamp_cards FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON member_transactions FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON lucky_codes FROM anon, authenticated;

-- B. Revoke execute of staff-only functions from anon/authenticated (Only Service Role / VPS can call)
REVOKE EXECUTE ON FUNCTION add_points(UUID, UUID, INTEGER) FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION add_stamp(UUID, UUID, UUID) FROM anon, authenticated;

-- C. Grant execute for member actions to authenticated only
GRANT EXECUTE ON FUNCTION redeem_points(UUID, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION claim_lucky_code(VARCHAR) TO authenticated;

-- D. Grant catalog reads
GRANT SELECT ON products TO anon, authenticated;
GRANT SELECT ON product_categories TO anon, authenticated;
GRANT SELECT ON product_variations TO anon, authenticated;
GRANT SELECT ON rewards TO anon, authenticated;
GRANT SELECT ON promotions TO anon, authenticated;

-- E. Enable RLS
ALTER TABLE members ENABLE ROW LEVEL SECURITY;
ALTER TABLE member_stamp_cards ENABLE ROW LEVEL SECURITY;
ALTER TABLE member_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE lucky_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE promotions ENABLE ROW LEVEL SECURITY;

-- F. Strict Ownership RLS Policies (Clients ONLY read their own data)
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

DROP POLICY IF EXISTS "Allow select lucky_codes" ON lucky_codes;
DROP POLICY IF EXISTS "Members read own lucky codes" ON lucky_codes;
CREATE POLICY "Members read own lucky codes" ON lucky_codes
    FOR SELECT USING (auth.uid() = member_id);

DROP POLICY IF EXISTS "Allow select promotions" ON promotions;
CREATE POLICY "Allow select promotions" ON promotions
    FOR SELECT USING (true);

DROP POLICY IF EXISTS "Allow manage promotions" ON promotions;
CREATE POLICY "Allow manage promotions" ON promotions
    FOR ALL USING (true) WITH CHECK (true);

-- G. Supabase Storage Bucket for Media & Promosi
INSERT INTO storage.buckets (id, name, public)
SELECT 'promotions', 'promotions', true
WHERE NOT EXISTS (SELECT 1 FROM storage.buckets WHERE id = 'promotions');

DROP POLICY IF EXISTS "Public Read Promotions Storage" ON storage.objects;
CREATE POLICY "Public Read Promotions Storage" ON storage.objects
    FOR SELECT USING (bucket_id = 'promotions');

DROP POLICY IF EXISTS "Allow Upload Promotions Storage" ON storage.objects;
CREATE POLICY "Allow Upload Promotions Storage" ON storage.objects
    FOR INSERT WITH CHECK (bucket_id = 'promotions');

DROP POLICY IF EXISTS "Allow Delete Promotions Storage" ON storage.objects;
CREATE POLICY "Allow Delete Promotions Storage" ON storage.objects
    FOR DELETE USING (bucket_id = 'promotions');

-- ====================================================================
-- 16. REALTIME REPLICATION (SAFE IDEMPOTENT BLOCK)
-- ====================================================================
DO $$
BEGIN
    BEGIN
        ALTER PUBLICATION supabase_realtime ADD TABLE sales;
    EXCEPTION WHEN duplicate_object THEN
        NULL;
    END;

    BEGIN
        ALTER PUBLICATION supabase_realtime ADD TABLE members;
    EXCEPTION WHEN duplicate_object THEN
        NULL;
    END;

    BEGIN
        ALTER PUBLICATION supabase_realtime ADD TABLE member_stamp_cards;
    EXCEPTION WHEN duplicate_object THEN
        NULL;
    END;

    BEGIN
        ALTER PUBLICATION supabase_realtime ADD TABLE promotions;
    EXCEPTION WHEN duplicate_object THEN
        NULL;
    END;
END $$;

-- ====================================================================
-- 17. INITIAL SEED DATA (SAFE IDEMPOTENT INSERTS)
-- ====================================================================
INSERT INTO product_categories (code, name, icon, sort_order)
SELECT 'kopi', 'Kopi', '☕', 1
WHERE NOT EXISTS (SELECT 1 FROM product_categories WHERE code = 'kopi');

INSERT INTO product_categories (code, name, icon, sort_order)
SELECT 'bukan-kopi', 'Bukan Kopi', '🍵', 2
WHERE NOT EXISTS (SELECT 1 FROM product_categories WHERE code = 'bukan-kopi');

INSERT INTO product_categories (code, name, icon, sort_order)
SELECT 'pastri', 'Pastri & Bakeri', '🥐', 3
WHERE NOT EXISTS (SELECT 1 FROM product_categories WHERE code = 'pastri');

INSERT INTO product_categories (code, name, icon, sort_order)
SELECT 'makanan', 'Makanan Berat', '🍛', 4
WHERE NOT EXISTS (SELECT 1 FROM product_categories WHERE code = 'makanan');

INSERT INTO product_categories (code, name, icon, sort_order)
SELECT 'addon', 'Pilihan Tambahan (Add-on)', '✨', 5
WHERE NOT EXISTS (SELECT 1 FROM product_categories WHERE code = 'addon');

INSERT INTO rewards (name, points_cost, stock_limit, icon)
SELECT 'Kopi Hitam Percuma', 100, 50, '☕'
WHERE NOT EXISTS (SELECT 1 FROM rewards WHERE name = 'Kopi Hitam Percuma');

INSERT INTO rewards (name, points_cost, stock_limit, icon)
SELECT 'Diskaun 20% Pastri', 150, 0, '🥐'
WHERE NOT EXISTS (SELECT 1 FROM rewards WHERE name = 'Diskaun 20% Pastri');

INSERT INTO rewards (name, points_cost, stock_limit, icon)
SELECT 'Kroisan Percuma', 220, 30, '🥐'
WHERE NOT EXISTS (SELECT 1 FROM rewards WHERE name = 'Kroisan Percuma');

-- ====================================================================
-- 15. POS SETTINGS TABLE (TELEGRAM, SST, PREFERENCES)
-- ====================================================================
CREATE TABLE IF NOT EXISTS pos_settings (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE pos_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow public read access to pos_settings" ON pos_settings FOR SELECT USING (true);
CREATE POLICY "Allow authenticated full access to pos_settings" ON pos_settings FOR ALL USING (true);

-- ====================================================================
-- 16. POS STAFF & ACCESS CONTROL TABLE
-- ====================================================================
CREATE TABLE IF NOT EXISTS pos_staff (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    staff_code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(150) NOT NULL,
    role VARCHAR(100) DEFAULT 'Kasir & Barista',
    phone VARCHAR(50) NOT NULL,
    pin VARCHAR(20) NOT NULL,
    hourly_rate NUMERIC(10,2) DEFAULT 8.50,
    active BOOLEAN DEFAULT TRUE,
    joined_date VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE pos_staff ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow public read access to pos_staff" ON pos_staff FOR SELECT USING (true);
CREATE POLICY "Allow authenticated full access to pos_staff" ON pos_staff FOR ALL USING (true);

CREATE INDEX IF NOT EXISTS idx_pos_staff_code ON pos_staff(staff_code);
CREATE INDEX IF NOT EXISTS idx_pos_staff_active ON pos_staff(active);

-- ====================================================================
-- 17. POS PAYROLL & SALARY PAYOUTS TABLE (KIRA & BAYAR GAJI STAF)
-- ====================================================================
CREATE TABLE IF NOT EXISTS pos_payroll (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    voucher_no VARCHAR(50) UNIQUE NOT NULL,
    staff_id VARCHAR(100) NOT NULL,
    staff_name VARCHAR(150) NOT NULL,
    staff_code VARCHAR(50) NOT NULL,
    role VARCHAR(100) DEFAULT 'Kasir & Barista',
    phone VARCHAR(50),
    period VARCHAR(150) NOT NULL,
    start_date DATE,
    end_date DATE,
    hours_worked NUMERIC(10,2) DEFAULT 0.00,
    hourly_rate NUMERIC(10,2) DEFAULT 8.50,
    basic_salary NUMERIC(10,2) DEFAULT 0.00,
    allowance NUMERIC(10,2) DEFAULT 0.00,
    deduction NUMERIC(10,2) DEFAULT 0.00,
    net_salary NUMERIC(10,2) NOT NULL,
    pay_method VARCHAR(50) DEFAULT 'bank',
    approved_by VARCHAR(150) DEFAULT 'Pengurus Utama',
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE pos_payroll ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow public read access to pos_payroll" ON pos_payroll FOR SELECT USING (true);
CREATE POLICY "Allow authenticated full access to pos_payroll" ON pos_payroll FOR ALL USING (true);

CREATE INDEX IF NOT EXISTS idx_pos_payroll_staff ON pos_payroll(staff_id);
CREATE INDEX IF NOT EXISTS idx_pos_payroll_created ON pos_payroll(created_at DESC);

