#!/usr/bin/env python3
"""Run the atomic import regressions on disposable PostgreSQL 16, without network."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
image = 'ultra-import-test:' + uuid.uuid4().hex
try:
    with tempfile.TemporaryDirectory(prefix='ultra-import-context-') as temporary:
        context = Path(temporary)
        # Never send the repository, canonical configuration or credentials to Docker.
        for name in ('import_protocol.py', 'test_import_protocol.py'):
            shutil.copyfile(ROOT / 'deploy/recovery' / name, context / name)
        (context / 'Dockerfile').write_text('''FROM postgres:16
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
COPY import_protocol.py test_import_protocol.py /tests/
USER postgres
WORKDIR /tests
ENV ULTRA_IMPORT_PROTOCOL_PG_TEST=1
CMD ["python3", "-B", "-m", "unittest", "-v", "test_import_protocol"]
''')
        subprocess.run(['docker', 'build', '--tag', image, str(context)], check=True)
        subprocess.run(['docker', 'run', '--rm', '--network', 'none', image], check=True)
finally:
    subprocess.run(['docker', 'image', 'rm', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
