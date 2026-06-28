#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Gunicorn configuration file for CRATOS FastAPI
Optimized for memory management and production deployment
"""
import multiprocessing

# Server socket
bind = "127.0.0.1:8080"
backlog = 2048

# Worker processes
workers = 6  # Adjust based on your needs (old config used 6)
worker_class = 'uvicorn.workers.UvicornWorker'
worker_connections = 1000
max_requests = 250  # Restart worker after this many requests to prevent memory leaks
max_requests_jitter = 15  # Add randomness to avoid all workers restarting at once
timeout = 120
keepalive = 5

# Graceful timeout for workers
graceful_timeout = 30

# Preload app to save memory by loading application before forking workers
preload_app = True

# Proxy configuration
# Only trust forwarded headers from the local reverse proxy (gunicorn binds to 127.0.0.1
# only, so this should be the loopback nginx is proxying from - never '*'). proxy_protocol
# is for TCP-level load balancers (e.g. HAProxy/ELB) that prefix connections with a PROXY
# protocol header; the documented nginx setup uses a standard HTTP proxy_pass, which does
# not send this, so leave it disabled unless your reverse proxy is configured to send it.
forwarded_allow_ips = '127.0.0.1'
proxy_protocol = False

# Process ownership (uncomment and adjust as needed)
user = 'fastapi'
group = 'fastapi'

# Working directory
chdir = '/opt/cratos-fastapi'

# Logging
errorlog = '/var/log/cratos/general.log'
accesslog = '-'  # Log to stdout
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Reload on code changes (disable in production)
reload = False  # Set to True for development

# Process naming
proc_name = 'cratos-fastapi'

# Server mechanics
daemon = False
pidfile = None
umask = 0o027  # rwxr-x--- : owner full access, group read, no access for others
tmp_upload_dir = None

# SSL (if needed, uncomment and configure)
# keyfile = '/path/to/keyfile'
# certfile = '/path/to/certfile'
