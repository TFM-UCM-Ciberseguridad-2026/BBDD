// ==========================================
// NEO4J SCHEMA DEFINITION FOR TFM
// ==========================================
// This script creates the necessary constraints and indexes
// to ensure data integrity and query performance.
// In Neo4j, creating a constraint automatically creates an index.

// 1. Constraints (Act as Primary Keys)
CREATE CONSTRAINT project_id IF NOT EXISTS FOR (p:Project) REQUIRE p.project_id IS UNIQUE;
CREATE CONSTRAINT network_id IF NOT EXISTS FOR (n:Network) REQUIRE n.network_id IS UNIQUE;
CREATE CONSTRAINT software_id IF NOT EXISTS FOR (s:Software) REQUIRE s.software_id IS UNIQUE;
CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE;
CREATE CONSTRAINT patch_id IF NOT EXISTS FOR (p:Patch) REQUIRE p.patch_id IS UNIQUE;
CREATE CONSTRAINT hardware_id IF NOT EXISTS FOR (h:Hardware) REQUIRE h.hardware_id IS UNIQUE;
CREATE CONSTRAINT endpoint_id IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.endpoint_id IS UNIQUE;

// 2. Additional Indexes for performance on frequent lookups
CREATE INDEX endpoint_hostname IF NOT EXISTS FOR (e:Endpoint) ON (e.hostname);
CREATE INDEX software_name IF NOT EXISTS FOR (s:Software) ON (s.nombre);
CREATE INDEX network_cidr IF NOT EXISTS FOR (n:Network) ON (n.cidr);
CREATE INDEX vulnerability_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity);
