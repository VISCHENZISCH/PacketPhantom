# PacketPhantom — image « capteur » : sans TUI, API + tableau de bord web sur le port 8787.
FROM python:3.13-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends curl build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH=/root/.cargo/bin:$PATH
WORKDIR /src
COPY . .
RUN pip install --no-cache-dir "maturin>=1.7,<2" && maturin build --release --out /wheels

FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
EXPOSE 8787
# Jeton d'API : variable PACKETPHANTOM_TOKEN (sinon un jeton aléatoire est affiché au démarrage).
ENTRYPOINT ["packetphantom", "--headless", "--api", "0.0.0.0:8787"]
