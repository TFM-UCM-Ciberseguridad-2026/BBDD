// ==========================================
// NEO4J MOCK DATA - SCENARIO: ATTACK PATHS
// ==========================================
// Limpiar base de datos
MATCH (n) DETACH DELETE n;

// Crear todo en una sola transacción para mantener las variables
CREATE 
  // 1. Endpoints
  (e1:Endpoint {endpoint_id: 1, hostname: "web-server-01", tipo: "Linux Server", internet_exposed: true}),
  (e2:Endpoint {endpoint_id: 2, hostname: "db-server-01", tipo: "Windows Server", internet_exposed: false}),

  // 2. Vulnerabilidades Clásicas
  (v_rce:Vulnerability {cve_id: "CVE-2017-5638", description: "Apache Struts RCE (Initial Access)", severity: "CRITICAL"}),
  (v_privesc:Vulnerability {cve_id: "CVE-2021-4034", description: "Polkit PwnKit (Privilege Escalation)", severity: "HIGH"}),
  (v_lateral:Vulnerability {cve_id: "CVE-2017-0144", description: "EternalBlue SMB RCE (Lateral Movement)", severity: "CRITICAL"}),

  // 3. Software
  (s_struts:Software {software_id: 1, nombre: "Apache Struts", version: "2.3.5"}),
  (s_polkit:Software {software_id: 2, nombre: "Polkit", version: "0.105"}),
  (s_smb:Software {software_id: 3, nombre: "Windows SMBv1 Server", version: "1.0"}),

  // 4. Relación Endpoint -> Software (La máquina ejecuta el software)
  (e1)-[:RUNS]->(s_struts),
  (e1)-[:RUNS]->(s_polkit),
  (e2)-[:RUNS]->(s_smb),

  // 5. Vincular Software con CVEs
  (s_struts)-[:VULNERABLE_TO]->(v_rce),
  (s_polkit)-[:VULNERABLE_TO]->(v_privesc),
  (s_smb)-[:VULNERABLE_TO]->(v_lateral),

  // ==========================================
  // GRAFO DE ATAQUE (ATTACK GRAPH)
  // ==========================================

  // A. Acceso Inicial desde Internet
  (n_internet:Network {nombre: "Internet", cidr: "0.0.0.0/0"}),
  // El atacante llega al servicio expuesto (Apache Struts)
  (n_internet)-[:CAN_REACH]->(s_struts), 
  // La vulnerabilidad del software compromete la máquina
  (v_rce)-[:COMPROMISES {privilege_granted: "www-data", technique: "T1190"}]->(e1),

  // B. Escalada de Privilegios
  // El atacante desde e1 interactúa con un servicio local (Polkit)
  (e1)-[:EXPLOITS_LOCAL {required_privilege: "www-data"}]->(s_polkit),
  (v_privesc)-[:ESCALATES_TO {privilege_granted: "root", technique: "T1068"}]->(e1),

  // C. Movimiento Lateral
  // Desde e1 (siendo root), ataca el servicio SMB expuesto por red en e2
  (e1)-[:EXPLOITS_REMOTE {required_privilege: "root"}]->(s_smb),
  (v_lateral)-[:COMPROMISES {privilege_granted: "SYSTEM", technique: "T1210"}]->(e2),

  // D. Parches y Mitigaciones (Cortafuegos)
  (p3:Patch {patch_id: 3, name: "MS17-010 Security Update"}),
  (p3)-[:REMEDIATES]->(v_lateral);
