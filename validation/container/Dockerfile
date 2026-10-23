FROM python:3.11.14-slim-bookworm@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d
COPY requirements.lock /opt/pqscan/requirements.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r /opt/pqscan/requirements.lock
LABEL org.pqscan.validation.profile="pqcrypto-0.3.4-v1"
USER 65534:65534
WORKDIR /tmp
