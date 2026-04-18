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
forwarded_allow_ips = '*'
proxy_protocol = True

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
umask = 0
tmp_upload_dir = None

# SSL (if needed, uncomment and configure)
# keyfile = '/path/to/keyfile'
# certfile = '/path/to/certfile'
