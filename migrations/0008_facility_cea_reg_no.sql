-- 0008_facility_cea_reg_no.sql
-- Add Clinical Establishment Registration Number to facility_settings
ALTER TABLE facility_settings ADD COLUMN cea_reg_no TEXT;
