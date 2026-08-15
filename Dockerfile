# The container tier the persona audits run against: a stock distro with bubblewrap and
# nothing else, so a journey sees what an operator's own image would give it.
#
#   make build && docker build -t bento-run .
#
# The binary is copied rather than built here so the image carries exactly the one under
# test - an image built from its own checkout is what let a 172-commit-stale bento-run
# report already-fixed findings as open.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap && rm -rf /var/lib/apt/lists/*
COPY bento /usr/local/bin/bento
