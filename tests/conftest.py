import os

# Unit tests never talk to real services; integration tests read credentials from .env.
os.environ.setdefault("BB_ENVIRONMENT", "test")
