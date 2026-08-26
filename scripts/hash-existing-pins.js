/**
 * ====================================================================
 * ONE-TIME MIGRATION SCRIPT: HASH EXISTING STAFF PINS TO BCRYPT
 * ====================================================================
 * Skrip ini membaca semua profil staf dalam jadual 'pos_staff' di Supabase.
 * Jika medan PIN masih dalam format plaintext (belum bermula dengan $2a$, $2b$, $2y$),
 * skrip akan menghasilkan hash bcrypt (cost factor 10) dan mengemas kini pangkalan data.
 *
 * Penggunaan:
 * node scripts/hash-existing-pins.js
 */

const path = require('path');
const bcrypt = require(path.resolve(__dirname, '../vps-backend/node_modules/bcryptjs'));
const { createClient } = require(path.resolve(__dirname, '../vps-backend/node_modules/@supabase/supabase-js'));
require(path.resolve(__dirname, '../vps-backend/node_modules/dotenv')).config({ path: path.resolve(__dirname, '../vps-backend/.env') });

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('❌ Ralat: SUPABASE_URL atau SUPABASE_SERVICE_ROLE_KEY tidak ditemui dalam vps-backend/.env');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

async function hashExistingPins() {
  console.log('====================================================================');
  console.log('🔐 MEMULAKAN PROSES HASHING PIN STAF KE BCRYPT (JADUAL: pos_staff)');
  console.log('====================================================================\n');

  try {
    // 1. Baca semua row dalam jadual pos_staff
    console.log('📡 Membaca senarai staf dari Supabase...');
    const { data: staffList, error } = await supabase
      .from('pos_staff')
      .select('*')
      .order('created_at', { ascending: true });

    if (error) {
      console.error('❌ Ralat membaca pos_staff:', error.message);
      return;
    }

    if (!staffList || staffList.length === 0) {
      console.log('ℹ️ Tiada rekod staf ditemui dalam jadual pos_staff.');
      return;
    }

    console.log(`📋 Ditemui ${staffList.length} rekod staf dalam jadual pos_staff.\n`);

    let updatedCount = 0;
    let skippedCount = 0;
    let failedCount = 0;

    // 2. Semak setiap row dan hash PIN plaintext
    for (const staff of staffList) {
      const currentPin = staff.pin ? String(staff.pin).trim() : '';

      if (!currentPin) {
        console.log(`⏩ [SKIP] Staf: ${staff.name} (${staff.staff_code || staff.id}) — Tiada PIN ditetapkan.`);
        skippedCount++;
        continue;
      }

      // Elak double-hashing jika sudah dalam format bcrypt ($2a$, $2b$, $2y$)
      if (currentPin.startsWith('$2a$') || currentPin.startsWith('$2b$') || currentPin.startsWith('$2y$')) {
        console.log(`⏩ [SKIP] Staf: ${staff.name} (${staff.staff_code || staff.id}) — PIN sudah disulitkan sebagai Bcrypt: ${currentPin.slice(0, 15)}...`);
        skippedCount++;
        continue;
      }

      console.log(`🔄 [HASHING] Staf: ${staff.name} (${staff.staff_code || staff.id}) — Menukar PIN plaintext '${currentPin}' ke Bcrypt...`);

      // Hash PIN menggunakan bcrypt (cost factor 10)
      const hashedPin = await bcrypt.hash(currentPin, 10);

      // UPDATE balik row di Supabase
      const { data: updatedData, error: updateErr } = await supabase
        .from('pos_staff')
        .update({
          pin: hashedPin,
          updated_at: new Date().toISOString()
        })
        .eq('id', staff.id)
        .select('*')
        .single();

      if (updateErr) {
        console.error(`❌ [GAGAL] Staf: ${staff.name} (${staff.staff_code}) — Ralat update: ${updateErr.message}`);
        if (updateErr.message.includes('character varying(20)')) {
          console.error(`   ⚠️ PERHATIAN: Saiz kolum 'pin' dalam jadual pos_staff adalah VARCHAR(20).`);
          console.error(`   Sila jalankan perintah SQL ini di Supabase SQL Editor:`);
          console.error(`   👉 ALTER TABLE pos_staff ALTER COLUMN pin TYPE TEXT;\n`);
        }
        failedCount++;
      } else {
        console.log(`✅ [BERJAYA] Staf: ${staff.name} (${staff.staff_code}) — PIN berjaya dikemaskini:`);
        console.log(`   Hash Baru: ${hashedPin}\n`);
        updatedCount++;
      }
    }

    console.log('====================================================================');
    console.log('📊 RINGKASAN PROSES HASHING:');
    console.log(`   - Berjaya di-hash & dikemaskini : ${updatedCount}`);
    console.log(`   - Dikeluarkan/Sudah di-hash    : ${skippedCount}`);
    console.log(`   - Gagal dikemaskini             : ${failedCount}`);
    console.log('====================================================================\n');

    // 3. Paparkan kandungan jadual pos_staff terkini
    console.log('📋 PAPARAN JADUAL pos_staff TERKINI DI SUPABASE:');
    const { data: latestStaff } = await supabase
      .from('pos_staff')
      .select('id, staff_code, name, role, phone, pin, active, joined_date')
      .order('created_at', { ascending: true });

    if (latestStaff) {
      console.table(latestStaff.map(s => ({
        ID: s.id,
        Kod: s.staff_code,
        Nama: s.name,
        Jawatan: s.role,
        Telefon: s.phone || '-',
        'Bcrypt PIN Hash': s.pin,
        Aktif: s.active ? 'Ya' : 'Tidak'
      })));
    }

  } catch (err) {
    console.error('❌ Ralat luar jangkaan semasa menjalankan skrip:', err);
  }
}

hashExistingPins();
