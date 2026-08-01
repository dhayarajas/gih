# Ghost Identity Hunter - Neo4j Integration Guide

## Overview
Ghost Identity Hunter now supports Neo4j graph database for advanced identity correlation analysis. This provides persistent graph storage, scalable analysis, and powerful graph querying capabilities beyond the in-memory NetworkX implementation.

## Benefits of Neo4j Integration

### **Advantages Over NetworkX**
- **Persistent Storage**: Graph data persists between investigations
- **Scalability**: Handles millions of nodes/edges efficiently
- **Native Graph Database**: Optimized for graph operations
- **Cypher Query Language**: Powerful graph querying capabilities
- **Built-in Algorithms**: Centrality, pathfinding, community detection
- **ACID Transactions**: Data integrity guarantees
- **Real-time Queries**: Sub-second response times for complex queries
- **Cross-Investigation Analysis**: Query graph data across multiple investigations

### **Use Cases**
- Large-scale investigations with thousands of artifacts
- Historical analysis of identity patterns
- Cross-investigation correlation and pattern matching
- Real-time graph exploration and visualization
- Advanced graph analytics and metrics

## Installation

### **Option 1: Docker Deployment (Recommended)**

#### **Kali Linux Docker with Neo4j**
```bash
# Clone repository
git clone https://github.com/dhayarajas/gih.git
cd gih

# Build and start with Neo4j
docker-compose -f docker-compose.kali.yml up -d

# Neo4j is automatically started with the container
# Access Neo4j Browser at http://localhost:7474
# Default credentials: neo4j / ghosthunter_password
```

#### **Standard Docker with Neo4j**
```bash
# Add Neo4j service to docker-compose.yml
# See docker-compose.kali.yml for reference configuration
```

### **Option 2: Local Neo4j Installation**

#### **Install Neo4j**
```bash
# On Ubuntu/Debian
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt update
sudo apt install neo4j

# On Mac with Homebrew
brew install neo4j

# Start Neo4j
sudo systemctl start neo4j  # Linux
neo4j start                  # Mac
```

#### **Configure Neo4j**
```bash
# Set initial password
# Access Neo4j Browser at http://localhost:7474
# Default credentials: neo4j / neo4j
# Change password to your preferred password
```

#### **Install Python Dependencies**
```bash
# Install Ghost Identity Hunter with Neo4j support
pip install -e ".[dev]"
# Neo4j driver is included in requirements.txt
```

### **Option 3: Neo4j Aura (Cloud)**

#### **Create Free Neo4j Aura Instance**
1. Visit https://neo4j.com/cloud/aura/
2. Sign up for free account
3. Create free database instance
4. Get connection details (URI, username, password)

#### **Configure Ghost Identity Hunter**
```bash
# Use Aura connection details
python -m src.cli investigate \
  --email "target@example.com" \
  --use-neo4j \
  --neo4j-uri "neo4j+s://your-instance.databases.neo4j.io" \
  --neo4j-user "neo4j" \
  --neo4j-password "your-aura-password"
```

## Usage

### **Basic Usage with Neo4j**
```bash
# Use Neo4j for graph correlation
python -m src.cli investigate \
  --email "target@example.com" \
  --use-neo4j

# With custom Neo4j configuration
python -m src.cli investigate \
  --email "target@example.com" \
  --use-neo4j \
  --neo4j-uri "bolt://localhost:7687" \
  --neo4j-user "neo4j" \
  --neo4j-password "your_password"

# Use with Docker
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli investigate \
  --email "target@example.com" \
  --use-neo4j
```

### **Environment Variables**
```bash
# Set Neo4j configuration via environment variables
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="your_password"
export USE_NEO4J="true"

# Run investigation
python -m src.cli investigate --email "target@example.com"
```

### **Fallback to NetworkX**
```bash
# If Neo4j connection fails, system automatically falls back to NetworkX
python -m src.cli investigate \
  --email "target@example.com" \
  --use-neo4j \
  --neo4j-uri "bolt://localhost:7687" \
  # If Neo4j is unavailable, NetworkX will be used automatically
```

## Neo4j Browser

### **Access Neo4j Browser**
```bash
# With Docker deployment
# Open http://localhost:7474 in your browser
# Login with: neo4j / ghosthunter_password

# With local installation
# Open http://localhost:7474 in your browser
# Login with your configured credentials
```

### **Example Cypher Queries**

#### **View All Artifacts**
```cypher
MATCH (a:Artifact)
RETURN a
LIMIT 25
```

#### **Find Identity Clusters**
```cypher
MATCH path = (a:Artifact)-[*]-(b:Artifact)
WITH a, collect(DISTINCT b) as component
WHERE size(component) > 1
RETURN component, size(component) as cluster_size
ORDER BY cluster_size DESC
```

#### **Find High-Confidence Connections**
```cypher
MATCH (a:Artifact)-[r:LINKED_TO]->(b:Artifact)
WHERE r.confidence > 0.8
RETURN a, b, r.confidence
ORDER BY r.confidence DESC
```

#### **Cross-Investigation Analysis**
```cypher
MATCH (a:Artifact)
WHERE a.investigation_id IN ['INV-abc123', 'INV-def456']
WITH a.value as value, collect(DISTINCT a.investigation_id) as investigations
WHERE size(investigations) > 1
RETURN value, investigations
```

#### **Find Risk Indicators**
```cypher
MATCH (a:Artifact)
WHERE a.metadata CONTAINS 'risk_indicators'
RETURN a.artifact_type, a.value, a.metadata
```

## Advanced Features

### **Cross-Investigation Correlation**
```python
from src.modules.correlation_neo4j import Neo4jCorrelation

correlation = Neo4jCorrelation(
    uri="bolt://localhost:7687",
    user="neo4j",
    password="password"
)

# Analyze correlations across multiple investigations
cross_analysis = correlation.cross_investigation_analysis(
    investigation_ids=["INV-abc123", "INV-def456", "INV-ghi789"]
)

print(f"Common artifacts: {len(cross_analysis['common_artifacts'])}")
print(f"Common patterns: {len(cross_analysis['common_patterns'])}")
```

### **Artifact Connection Analysis**
```python
# Get all connections for a specific artifact
connections = correlation.get_artifact_connections(
    artifact_id="artifact-123",
    max_depth=2
)

print(f"Found {connections['connection_count']} connections")
for conn in connections['connections']:
    print(f"  - {conn['artifact_type']}: {conn['value']} (distance: {conn['distance']})")
```

### **Identity Cluster Extraction**
```python
# Extract identity clusters from investigation
clusters = correlation.find_identity_clusters("INV-abc123")

for cluster in clusters:
    print(f"Cluster {cluster['cluster_id']}:")
    print(f"  Size: {cluster['size']}")
    print(f"  Types: {cluster['artifact_types']}")
    print(f"  Confidence: {cluster['confidence']}")
```

## Performance Tuning

### **Neo4j Configuration**
```yaml
# In docker-compose.kali.yml
environment:
  - NEO4J_dbms_memory_heap_initial__size=512m
  - NEO4J_dbms_memory_heap_max__size=2G
  - NEO4J_dbms_memory_pagecache_size=1G
```

### **Index Optimization**
```cypher
# Create additional indexes for performance
CREATE INDEX artifact_confidence IF NOT EXISTS
FOR (a:Artifact) ON (a.confidence)

CREATE INDEX link_confidence IF NOT EXISTS
FOR ()-[r:LINKED_TO]->() ON (r.confidence)
```

### **Query Optimization**
```cypher
# Use PROFILE to analyze query performance
PROFILE MATCH (a:Artifact)-[r:LINKED_TO]->(b:Artifact)
WHERE a.investigation_id = 'INV-abc123'
RETURN a, b, r
```

## Troubleshooting

### **Connection Issues**
```bash
# Check Neo4j is running
sudo systemctl status neo4j  # Linux
neo4j status                  # Mac

# Check Neo4j logs
sudo journalctl -u neo4j      # Linux
tail -f /usr/local/var/log/neo4j/neo4j.log  # Mac

# Test connection
python -c "from neo4j import GraphDatabase; driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'password')); driver.verify_connectivity()"
```

### **Docker Issues**
```bash
# Check Neo4j container status
docker-compose -f docker-compose.kali.yml ps

# View Neo4j logs
docker-compose -f docker-compose.kali.yml logs neo4j

# Restart Neo4j container
docker-compose -f docker-compose.kali.yml restart neo4j
```

### **Memory Issues**
```bash
# Increase Neo4j memory allocation
# Edit docker-compose.kali.yml
environment:
  - NEO4J_dbms_memory_heap_max__size=4G
  - NEO4J_dbms_memory_pagecache_size=2G
```

### **Schema Issues**
```bash
# Reset Neo4j database (CAUTION: deletes all data)
docker-compose -f docker-compose.kali.yml down -v
docker-compose -f docker-compose.kali.yml up -d
```

## Migration from NetworkX

### **Gradual Migration**
1. Start with NetworkX (default)
2. Test Neo4j with `--use-neo4j` flag
3. Compare results between NetworkX and Neo4j
4. Gradually switch to Neo4j for production
5. Keep NetworkX as fallback

### **Data Migration**
```bash
# Existing investigations work with both backends
# No manual migration required
# New investigations use configured backend
```

### **Configuration Migration**
```bash
# Update scripts to use Neo4j flags
# Old: python -m src.cli investigate --email "target@example.com"
# New: python -m src.cli investigate --email "target@example.com" --use-neo4j
```

## Security Considerations

### **Authentication**
- Change default Neo4j password
- Use strong passwords for production
- Consider using Neo4j Aura for cloud deployments
- Enable SSL/TLS for remote connections

### **Network Security**
```yaml
# In docker-compose.kali.yml
# Remove port mappings for external access
# ports:
#   - "7474:7474"  # Comment out for security
#   - "7687:7687"  # Comment out for security
```

### **Data Privacy**
- Neo4j data persists between investigations
- Regular backup of Neo4j data
- Secure deletion of sensitive investigations
- Access control for Neo4j Browser

## Backup and Restore

### **Backup Neo4j Data**
```bash
# With Docker
docker exec ghost-hunter-neo4j neo4j-admin backup --backup-dir=/backups --from=docker

# With local installation
neo4j-admin backup --backup-dir=/path/to/backup --from=neo4j
```

### **Restore Neo4j Data**
```bash
# With Docker
docker exec ghost-hunter-neo4j neo4j-admin restore --from=/backups --database=neo4j

# With local installation
neo4j-admin restore --from=/path/to/backup --database=neo4j
```

### **Volume Backup**
```bash
# Backup Docker volumes
docker run --rm -v gih_neo4j_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/neo4j_backup.tar.gz /data
```

## Best Practices

### **When to Use Neo4j**
- Large investigations (>1000 artifacts)
- Cross-investigation analysis
- Historical pattern analysis
- Complex graph queries
- Real-time graph exploration
- Production deployments

### **When to Use NetworkX**
- Small investigations (<100 artifacts)
- Quick analysis and testing
- Development and debugging
- Limited system resources
- Temporary investigations

### **Performance Tips**
- Use appropriate indexes
- Limit query result sets
- Use query profiling
- Monitor memory usage
- Regular database maintenance

## Support and Resources

### **Documentation**
- [Neo4j Documentation](https://neo4j.com/docs/)
- [Cypher Query Language](https://neo4j.com/docs/cypher-manual/)
- [Neo4j Python Driver](https://neo4j.com/docs/python-manual/)

### **Community**
- [Neo4j Community Forum](https://community.neo4j.com/)
- [Neo4j Stack Overflow](https://stackoverflow.com/questions/tagged/neo4j)
- [Ghost Identity Hunter GitHub](https://github.com/dhayarajas/gih)

## Summary

Neo4j integration provides Ghost Identity Hunter with enterprise-grade graph database capabilities, enabling scalable, persistent, and powerful identity correlation analysis. The system supports both NetworkX (default) and Neo4j backends, with automatic fallback and seamless switching between the two.
