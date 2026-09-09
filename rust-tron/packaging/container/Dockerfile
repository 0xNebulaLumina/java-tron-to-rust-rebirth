# syntax=docker/dockerfile:1.7
ARG RUNTIME_BASE
FROM scratch AS verified-staging
COPY . /staging/
FROM ${RUNTIME_BASE}
COPY --from=verified-staging --chown=65532:65532 /staging/bin/tron-release-verify /usr/local/bin/tron-release-verify
COPY --from=verified-staging --chown=65532:65532 /staging/entrypoint.sh /usr/local/bin/entrypoint.sh
USER 65532:65532
VOLUME ["/opt/tron","/var/lib/tron"]
EXPOSE 18888/tcp 18888/udp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["fullnode"]
