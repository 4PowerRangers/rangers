FROM bkimminich/juice-shop:v20.2.0

COPY --chown=65532:65532 environments/juice_shop/integrations/sequelize_observer.cjs /juice-shop/ranger-sequelize-observer.cjs
ENV NODE_OPTIONS="--require=/juice-shop/ranger-sequelize-observer.cjs"
ENV RANGER_DB_OBSERVER="host.docker.internal:8765"
