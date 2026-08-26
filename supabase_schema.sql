-- ====================================================================
-- ARANG COFFEE POS & LOYALTY SYSTEM — SUPABASE POSTGRESQL SCHEMA
-- Scalable, High-Performance, Multi-Tenant Ready Architecture
-- ====================================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ====================================================================
-- 2. ENUMS & DOMAINS
-- ====================================================================
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('admin', 'manager', 'cashier', 'kitchen');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE order_type AS ENUM ('dinein', 'takeaway', 'delivery');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE payment_method AS ENUM ('cash', 'qr_duitnow', 'card', 'ewallet', 'points');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE order_status AS ENUM ('paid', 'pending', 'cancelled', 'refunded');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE stamp_card_status AS ENUM ('collecting', 'unclaimed', 'claimed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ====================================================================
-- 3. OUTLETS / CAWANGAN & BUSINESS PROFILE
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
-- 7. MENU PRODUCT CATEGORIES
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

-- ====================================================================
-- 8. PRODUCTS (MENU ITEM)
-- ====================================================================
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
-- 9. SALES TRANSACTIONS & RECEIPT ORDERS
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
CREATE INDEX IF NOT EXISTS idx_sale_items_product ON sale_items(product_id);

-- ====================================================================
-- 10. REWARDS CATALOG & REDEMPTION
-- ====================================================================
CREATE TABLE IF NOT EXISTS rewards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(200) NOT NULL,
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

-- ====================================================================
-- 11. ADS & PROMOTIONS (POPUP & BANNER)
-- ====================================================================
CREATE TABLE IF NOT EXISTS promotions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(200) NOT NULL,
    description TEXT,
    media_url TEXT NOT NULL,
    media_type VARCHAR(20) DEFAULT 'image',
    badge_label VARCHAR(100) DEFAULT '🔥 Tawaran Khas',
    action_url TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    sort_order INT DEFAULT 0,
    start_date TIMESTAMPTZ DEFAULT NOW(),
    end_date TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ====================================================================
-- 12. WHATSAPP BOT LOG & PENDING OTP REQUESTS (AUDIT TRAIL)
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
-- 13. SALARY & ATTENDANCE RECORDS (KIRA & BAYAR GAJI)
-- ====================================================================
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
-- 14. REALTIME REPLICATION CONFIGURATION (SUPABASE)
-- ====================================================================
ALTER PUBLICATION supabase_realtime ADD TABLE sales;
ALTER PUBLICATION supabase_realtime ADD TABLE members;
ALTER PUBLICATION supabase_realtime ADD TABLE member_stamp_cards;
ALTER PUBLICATION supabase_realtime ADD TABLE promotions;

-- ====================================================================
-- 15. SEED INITIAL DATA (DEFAULTS)
-- ====================================================================
INSERT INTO product_categories (code, name, icon, sort_order) VALUES
('kopi', 'Kopi', '☕', 1),
('bukan-kopi', 'Bukan Kopi', '🍵', 2),
('pastri', 'Pastri & Bakeri', '🥐', 3),
('makanan', 'Makanan Berat', '🍛', 4),
('addon', 'Pilihan Tambahan (Add-on)', '✨', 5)
ON CONFLICT (code) DO NOTHING;

INSERT INTO rewards (name, points_cost, stock_limit, icon) VALUES
('Kopi Hitam Percuma', 100, 50, '☕'),
('Diskaun 20% Pastri', 150, 0, '🥐'),
('Kroisan Percuma', 220, 30, '🥐')
ON CONFLICT DO NOTHING;
