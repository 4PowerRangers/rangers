FROM rangers-juice-shop:latest

COPY docker/scenarios/JS-S6-001/enable-upload.js /tmp/enable-js-s6-001-upload.js
RUN ["/nodejs/bin/node", "/tmp/enable-js-s6-001-upload.js"]
COPY scenarios/JS-S6-001/assets/legal.md /juice-shop/ftp/legal.md
COPY docker/scenarios/JS-S6-001/start.js /tmp/start-js-s6-001.js
# The vulnerable extractor runs as the Juice Shop user. Make only the
# designated proof file writable so the Zip Slip proof is reproducible while
# keeping the rest of the image unchanged.
USER root
RUN ["/nodejs/bin/node", "-e", "const fs=require('fs'); fs.chmodSync('/juice-shop/ftp', 0o777); fs.chmodSync('/juice-shop/ftp/legal.md', 0o666); fs.chmodSync('/juice-shop/uploads/complaints', 0o777)"]
USER 65532
CMD ["/tmp/start-js-s6-001.js"]
