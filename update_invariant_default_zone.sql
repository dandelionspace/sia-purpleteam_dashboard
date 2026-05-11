BEGIN;

WITH zone_map(invariant_id, default_zone) AS (
  VALUES
    ('INV-STD-01', 'argos-mgmt'),
    ('INV-STD-02', 'argos-mgmt'),
    ('INV-STD-03', 'argos-security'),
    ('INV-STD-04', 'argos-security'),
    ('INV-STD-05', 'argos-ops'),
    ('INV-STD-06', 'argos-ops'),
    ('INV-STD-07', 'argos-ops'),
    ('INV-STD-08', 'argos-dmz'),
    ('INV-STD-09', 'argos-data'),
    ('INV-STD-10', 'argos-security'),
    ('INV-STD-11', 'argos-security'),
    ('INV-STD-12', 'argos-data'),
    ('INV-STD-13', 'argos-ops'),
    ('INV-STD-14', 'argos-mgmt'),

    ('INV-STD-CAND-WEB-01', 'argos-dmz'),
    ('INV-STD-CAND-WEB-02', 'argos-dmz'),
    ('INV-STD-CAND-WEB-03', 'argos-dmz'),

    ('INV-ARG-01', 'argos-ops'),
    ('INV-ARG-02', 'argos-ops'),
    ('INV-ARG-03', 'argos-ops'),
    ('INV-ARG-04', 'argos-data'),
    ('INV-ARG-05', 'argos-data'),
    ('INV-ARG-06', 'argos-ops'),
    ('INV-ARG-07', 'argos-ops'),
    ('INV-ARG-08', 'argos-deploy'),

    ('INV-ARG-S2-01', 'argos-dmz'),
    ('INV-ARG-S2-02', 'argos-signing'),
    ('INV-ARG-S2-03', 'argos-ops'),
    ('INV-ARG-S2-04', 'argos-deploy'),
    ('INV-ARG-S2-05', 'argos-deploy'),
    ('INV-ARG-S2-06', 'argos-signing'),
    ('INV-ARG-S2-07', 'argos-deploy'),
    ('INV-ARG-S2-08', 'argos-deploy'),
    ('INV-ARG-S2-09', 'argos-deploy'),
    ('INV-ARG-S2-10', 'argos-security'),
    ('INV-ARG-S2-11', 'argos-deploy'),
    ('INV-ARG-S2-12', 'argos-deploy'),
    ('INV-ARG-S2-13', 'argos-deploy'),

    ('INV-ARG-S3-01', 'argos-mgmt'),
    ('INV-ARG-S3-05', 'argos-data'),
    ('INV-ARG-S3-06', 'argos-data'),
    ('INV-ARG-S3-07', 'argos-security'),
    ('INV-ARG-S3-08', 'argos-security'),

    ('INV-ARG-S4-01', 'argos-dmz'),
    ('INV-ARG-S4-02', 'argos-security'),
    ('INV-ARG-S4-03', 'argos-mgmt'),
    ('INV-ARG-S4-04', 'argos-data'),
    ('INV-ARG-S4-05', 'argos-security'),
    ('INV-ARG-S4-06', 'argos-data'),
    ('INV-ARG-S4-07', 'argos-security'),
    ('INV-ARG-S4-08', 'argos-security'),
    ('INV-ARG-S4-09', 'argos-data'),
    ('INV-ARG-S4-10', 'argos-dmz'),
    ('INV-ARG-S4-11', 'argos-mgmt'),
    ('INV-ARG-S4-12', 'argos-security'),
    ('INV-ARG-S4-13', 'argos-security')
)
UPDATE invariants AS i
SET default_zone = z.default_zone
FROM zone_map AS z
WHERE i.invariant_id = z.invariant_id;

COMMIT;
