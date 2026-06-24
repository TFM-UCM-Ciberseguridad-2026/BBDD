# TFM - Motor de Base de Datos y Rutas de Ataque (Neo4j)

Este directorio contiene la infraestructura de base de datos orientada a grafos (Neo4j) que actúa como el núcleo (core) del TFM para el cálculo de rutas de ataque y relaciones entre activos.

Se ha migrado de un modelo relacional tradicional a un modelo de grafos para optimizar las consultas complejas de *Attack Paths*, alineándose con la estructura de MITRE ATT&CK.

## Requisitos
- Docker
- Docker Compose

## Cómo arrancar el entorno

1. Abre una terminal en este directorio (`BBDD`).
2. Levanta el contenedor de Neo4j en segundo plano:
   ```bash
   docker-compose up -d
   ```
3. Verifica que el contenedor está corriendo:
   ```bash
   docker ps | grep neo4j
   ```

## Cómo cargar el esquema y los datos de prueba

Para interactuar con la base de datos, entra a la interfaz gráfica:
1. Abre tu navegador y ve a: [http://localhost:7474](http://localhost:7474)
2. Inicia sesión con:
   - **Username**: `neo4j`
   - **Password**: `password`

### 1. Cargar el Esquema (Constraints & Indexes)
Abre el archivo `neo4j_schema.cypher`, copia todo su contenido y pégalo en la barra superior de comandos de Neo4j Browser. Pulsa `Play` (o Ctrl+Enter). Esto creará los índices para asegurar el rendimiento.

### 2. Cargar el Escenario de Prueba (Mock Data)
Abre el archivo `neo4j_mock_data.cypher`, cópialo entero y ejecútalo igual. Esto creará un escenario completo con Redes, Servidores, Vulnerabilidades (Apache Struts, PwnKit, EternalBlue) y sus relaciones.

## Cómo probar los Attack Paths

Una vez los datos estén cargados, prueba las siguientes consultas en la consola de Neo4j para ver el potencial del motor:

**Ver todos los activos, vulnerabilidades y parches:**
```cypher
MATCH (n) RETURN n
```

**Ver el camino de explotación desde Internet hasta la Base de Datos:**
```cypher
MATCH path = (net:Network {nombre: "Internet"})-[r:CAN_REACH|RUNS|VULNERABLE_TO|COMPROMISES|EXPLOITS_LOCAL|ESCALATES_TO|EXPLOITS_REMOTE*1..10]->(target:Endpoint {hostname: "db-server-01"})
RETURN path
```

**Escenario Avanzado: Simular el efecto de los Parches:**
En nuestros datos de prueba (`neo4j_mock_data.cypher`), hemos simulado que la base de datos Windows aplicó el parche para EternalBlue, pero el servidor Linux web sigue sin estar parcheado.

Si ejecutas esta consulta avanzada apuntando a la Base de Datos (que filtra los caminos que pasan por vulnerabilidades parcheadas):
```cypher
MATCH path = (net:Network {nombre: "Internet"})-[r:CAN_REACH|RUNS|VULNERABLE_TO|COMPROMISES|EXPLOITS_LOCAL|ESCALATES_TO|EXPLOITS_REMOTE*1..10]->(target:Endpoint {hostname: "db-server-01"})
WHERE NOT EXISTS {
  MATCH (v:Vulnerability)
  WHERE v IN nodes(path) AND (v)<-[:REMEDIATES]-(:Patch)
}
RETURN path
```
Verás que **no devuelve ningún resultado**. Esto demuestra gráficamente que la Base de Datos está segura, ya que el motor ha cortado el ataque al detectar el parche de EternalBlue.

**Ver hasta dónde llega el ataque (sin un objetivo fijo):**
```cypher
MATCH path = (net:Network {nombre: "Internet"})-[r:CAN_REACH|RUNS|VULNERABLE_TO|COMPROMISES|EXPLOITS_LOCAL|ESCALATES_TO|EXPLOITS_REMOTE*1..10]->(target:Endpoint)
WHERE NOT EXISTS {
  MATCH (v:Vulnerability)
  WHERE v IN nodes(path) AND (v)<-[:REMEDIATES]-(:Patch)
}
RETURN path
```
Verás que el grafo de ataque se detiene en el `web-server-01`, que sí sigue siendo vulnerable, y no avanza hacia la base de datos.

**Simulación en Caliente: Aplicar un nuevo parche y ver cómo se reduce el riesgo**
Imagina que el equipo de sistemas acaba de actualizar Polkit en el servidor Linux. Puedes introducir ese parche en tiempo real ejecutando esto:
```cypher
MATCH (v:Vulnerability {cve_id: "CVE-2021-4034"})
CREATE (p:Patch {patch_id: 2, name: "Polkit 0.105-31.1 Update"})-[:REMEDIATES]->(v)
```
Si ahora **vuelves a ejecutar la consulta del paso anterior** ("Ver hasta dónde llega el ataque"), verás que el grafo se reduce aún más: el atacante logra entrar al servidor web, pero ya no puede escalar a "root" porque la vulnerabilidad de escalada de privilegios acaba de ser mitigada.

**Bloqueo Total: Cortar el ataque de raíz (Initial Access)**
Finalmente, si el equipo decide parchear también la vulnerabilidad de entrada (Apache Struts), puedes inyectar este último parche:
```cypher
MATCH (v:Vulnerability {cve_id: "CVE-2017-5638"})
CREATE (p:Patch {patch_id: 1, name: "Struts 2.5.10.1 Update"})-[:REMEDIATES]->(v)
```
Si vuelves a ejecutar la consulta para ver hasta dónde llega el ataque, **no te devolverá ningún resultado**. ¡Has mitigado todo el grafo de ataque y la red vuelve a estar completamente segura!

> **Nota Visual**: Si en el grafo ves círculos verdes con números (1, 2, 3), haz clic en la píldora `Software` de la barra lateral izquierda y, en el menú que se despliega debajo, selecciona `nombre` en la sección de Caption. Esto mostrará el nombre real del software (Apache, Polkit, etc.).
