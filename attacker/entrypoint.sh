#!/bin/bash
ip route add 10.0.2.0/24 via 10.0.1.254 2>/dev/null || true
exec "$@"
