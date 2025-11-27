#!/bin/bash

# Development startup script for MobAI - Mobile Security Analyzer
# This script starts both backend and frontend for local development

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$PROJECT_DIR/backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== MobAI - Mobile Security Analyzer ===${NC}"
echo -e "${GREEN}Starting development environment...${NC}"
echo ""

# Create necessary directories
mkdir -p "$BACKEND_DIR/uploads"
mkdir -p "$BACKEND_DIR/data"

# Set environment variables
export UPLOAD_DIR="$BACKEND_DIR/uploads"
export DATA_DIR="$BACKEND_DIR/data"
export DATABASE_PATH="$BACKEND_DIR/data/mobile_analyzer.db"
export ALLOWED_ORIGINS="http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173"

# Check if virtual environment exists
if [ ! -d "$BACKEND_DIR/venv" ]; then
    echo -e "${YELLOW}Creating Python virtual environment...${NC}"
    python3 -m venv "$BACKEND_DIR/venv"
    source "$BACKEND_DIR/venv/bin/activate"
    pip install --upgrade pip
    pip install -r "$BACKEND_DIR/requirements.txt"
else
    source "$BACKEND_DIR/venv/bin/activate"
fi

# Check if node_modules exists
if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
    echo -e "${YELLOW}Installing frontend dependencies...${NC}"
    cd "$FRONTEND_DIR" && npm install
fi

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}Shutting down services...${NC}"
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    echo -e "${GREEN}Done!${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start backend
echo -e "${GREEN}Starting backend on http://localhost:8000${NC}"
cd "$BACKEND_DIR"
uvicorn main:app --reload --port 8000 --host 0.0.0.0 &
BACKEND_PID=$!

# Wait for backend to be ready
echo -e "${YELLOW}Waiting for backend to start...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
        echo -e "${GREEN}Backend is ready!${NC}"
        break
    fi
    sleep 1
done

# Start frontend
echo -e "${GREEN}Starting frontend on http://localhost:5173${NC}"
cd "$FRONTEND_DIR"
npm run dev &
FRONTEND_PID=$!

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}MobAI is running!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Backend API:  ${YELLOW}http://localhost:8000${NC}"
echo -e "API Docs:     ${YELLOW}http://localhost:8000/api/docs${NC}"
echo -e "Frontend:     ${YELLOW}http://localhost:5173${NC}"
echo ""
echo -e "Press ${RED}Ctrl+C${NC} to stop all services"
echo ""

# Wait for processes
wait
