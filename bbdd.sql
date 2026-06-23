CREATE DATABASE IF NOT EXISTS cmdb_vulnerabilidades
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE cmdb_vulnerabilidades;

DROP TABLE IF EXISTS Remediation;
DROP TABLE IF EXISTS Finding;
DROP TABLE IF EXISTS Software_Vulnerability;
DROP TABLE IF EXISTS Installation;
DROP TABLE IF EXISTS Connection;
DROP TABLE IF EXISTS Endpoint;
DROP TABLE IF EXISTS Hardware;
DROP TABLE IF EXISTS Parche;
DROP TABLE IF EXISTS Vulnerabilidad;
DROP TABLE IF EXISTS Software;
DROP TABLE IF EXISTS Red;
DROP TABLE IF EXISTS Proyecto;

CREATE TABLE Proyecto (
    project_id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(255) NOT NULL,
    owner VARCHAR(255),
    criticality INT
);

CREATE TABLE Red (
    network_id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(255) NOT NULL,
    cidr VARCHAR(50),
    gateway_ip VARCHAR(50),
    vlan_id INT,
    zone VARCHAR(100)
);

CREATE TABLE Software (
    software_id INT AUTO_INCREMENT PRIMARY KEY,
    tipo VARCHAR(100),
    vendor VARCHAR(255),
    nombre VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    cpe VARCHAR(255),
    purl VARCHAR(255),
    release_date DATE,
    lifecycle_status VARCHAR(100)
);

CREATE TABLE Vulnerabilidad (
    cve_id VARCHAR(50) PRIMARY KEY, 
    description TEXT,
    cvss_vector VARCHAR(150),
    base_score FLOAT,
    severity VARCHAR(50),
    cwe VARCHAR(100),
    kev BOOLEAN,
    epss_score FLOAT,
    published_date DATE,
    last_modified DATE,
    source_type VARCHAR(255)
);

CREATE TABLE Parche (
    patch_id INT AUTO_INCREMENT PRIMARY KEY,
    vendor_patch_id VARCHAR(255),
    description TEXT,
    release_date DATE,
    url TEXT
);

CREATE TABLE Hardware (
    hardware_id INT AUTO_INCREMENT PRIMARY KEY,
    fabricante VARCHAR(255),
    modelo VARCHAR(255),
    cpu VARCHAR(150),
    ram_gb INT,
    almacenamiento_gb INT
);

CREATE TABLE Endpoint (
    endpoint_id INT AUTO_INCREMENT PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    tipo VARCHAR(100),
    estado VARCHAR(50),
    project_id INT,
    hardware_id INT,
    asset_criticality INT,
    environment VARCHAR(100),
    internet_exposed BOOLEAN,
    CONSTRAINT fk_endpoint_project FOREIGN KEY (project_id) REFERENCES Proyecto(project_id) ON DELETE SET NULL,
    CONSTRAINT fk_endpoint_hardware FOREIGN KEY (hardware_id) REFERENCES Hardware(hardware_id) ON DELETE SET NULL
);

CREATE TABLE Connection (
    endpoint_id INT,
    network_id INT,
    ip_address VARCHAR(50),
    first_seen DATE,
    last_seen DATE,
    PRIMARY KEY (endpoint_id, network_id),
    CONSTRAINT fk_connection_endpoint FOREIGN KEY (endpoint_id) REFERENCES Endpoint(endpoint_id) ON DELETE CASCADE,
    CONSTRAINT fk_connection_network FOREIGN KEY (network_id) REFERENCES Red(network_id) ON DELETE CASCADE
);

CREATE TABLE Installation (
    endpoint_id INT,
    software_id INT,
    install_path VARCHAR(500),
    first_seen DATE,
    last_seen DATE,
    status VARCHAR(50),
    PRIMARY KEY (endpoint_id, software_id),
    CONSTRAINT fk_installation_endpoint FOREIGN KEY (endpoint_id) REFERENCES Endpoint(endpoint_id) ON DELETE CASCADE,
    CONSTRAINT fk_installation_software KEY (software_id) REFERENCES Software(software_id) ON DELETE CASCADE
);

CREATE TABLE Software_Vulnerability (
    software_id INT,
    cve_id VARCHAR(50),
    matched_cpe VARCHAR(255),
    version_range VARCHAR(255),
    match_criteria_id VARCHAR(100),
    source VARCHAR(100),
    detected_at DATETIME, 
    match_confidence VARCHAR(50),
    PRIMARY KEY (software_id, cve_id),
    CONSTRAINT fk_sv_software FOREIGN KEY (software_id) REFERENCES Software(software_id) ON DELETE CASCADE,
    CONSTRAINT fk_sv_cve FOREIGN KEY (cve_id) REFERENCES Vulnerabilidad(cve_id) ON DELETE CASCADE
);

CREATE TABLE Finding (
    finding_id INT AUTO_INCREMENT PRIMARY KEY,
    endpoint_id INT,
    software_id INT,
    cve_id VARCHAR(50),
    risk_score FLOAT,
    risk_level VARCHAR(50),
    status VARCHAR(50),
    first_seen DATE,
    last_seen DATE,
    resolved_at DATE,
    CONSTRAINT fk_finding_endpoint FOREIGN KEY (endpoint_id) REFERENCES Endpoint(endpoint_id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_software FOREIGN KEY (software_id) REFERENCES Software(software_id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_cve FOREIGN KEY (cve_id) REFERENCES Vulnerabilidad(cve_id) ON DELETE CASCADE
);

CREATE TABLE Remediation (
    remediation_id INT AUTO_INCREMENT PRIMARY KEY,
    finding_id INT,
    patch_id INT,
    fixed_version VARCHAR(255),
    status VARCHAR(50),
    planned_at DATE,
    applied_at DATE,
    verified_at DATE,
    CONSTRAINT fk_remediation_finding FOREIGN KEY (finding_id) REFERENCES Finding(finding_id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_patch FOREIGN KEY (patch_id) REFERENCES Parche(patch_id) ON DELETE SET NULL
);
