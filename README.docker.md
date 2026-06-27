# Ghost Identity Hunter - Docker Deployment

## Quick Start

### Prerequisites
- Docker Desktop installed and running
- Docker Compose (included with Docker Desktop)

### Build and Run

#### Option 1: Using Docker Compose (Recommended)
```bash
# Clone and navigate to the project
git clone https://github.com/dhayarajas/gih.git
cd gih

# Build and start the container
docker-compose up --build

# Run in detached mode
docker-compose up -d --build
```

#### Option 2: Using Docker directly
```bash
# Build the image
docker build -t ghost-identity-hunter:latest .

# Run the container
docker run -it --rm \
  -v ghost_hunter_data:/home/ghosthunter/.ghost_hunter \
  -v $(pwd)/investigations:/app/investigations \
  ghost-identity-hunter:latest
```

## Usage

### Running Investigations
```bash
# Using docker-compose
docker-compose exec ghost-hunter python cli.py investigate \
  --phone "+1234567890" \
  --email "user@example.com" \
  --username "target_user"

# Using docker run
docker run -it --rm \
  -v ghost_hunter_data:/home/ghosthunter/.ghost_hunter \
  -v $(pwd)/investigations:/app/investigations \
  ghost-identity-hunter:latest investigate \
  --phone "+1234567890" \
  --email "user@example.com"
```

### Listing Investigations
```bash
docker-compose exec ghost-hunter python cli.py list
```

### Generating Reports
```bash
docker-compose exec ghost-hunter python cli.py report <investigation_id>
```

## Data Persistence

- **Database**: Stored in Docker volume `ghost_hunter_data`
- **Reports**: Mounted to `./investigations` directory
- **Configuration**: Environment variables in `docker-compose.yml`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PYTHONPATH` | `/app` | Python module path |
| `GHOST_HUNTER_DB_PATH` | `/home/ghosthunter/.ghost_hunter/investigations.db` | SQLite database location |

## Development

### Building for Development
```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

### Accessing Shell
```bash
docker-compose exec ghost-hunter /bin/bash
```

## Troubleshooting

### Docker Daemon Not Running
1. Start Docker Desktop
2. Verify with `docker version`

### Permission Issues
```bash
# On Linux, add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

### Volume Issues
```bash
# Remove and recreate volumes
docker-compose down -v
docker-compose up --build
```

## Security Notes

- Container runs as non-root user (`ghosthunter`)
- Database stored in persistent Docker volume
- No exposed ports (CLI-only application)
- Minimal base image (`python:3.11-slim`)
