# kbd: the OpenBasalt Knowledge server.
#
# Static binary on a distroless base, running as a non-root user. Run the
# container with a read-only root file system; kbd writes nothing except,
# when KBD_FETCH_URL is set, the fetched bundle into KBD_DATA (mount a
# small writable volume or tmpfs there). See docs/hosting.md.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/kbd ./cmd/kbd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kbd /kbd
USER 65532:65532
ENV KBD_ADDR=:8080 \
    KBD_DATA=/data \
    KBD_TRUST=/etc/kbd/trust.json \
    KBD_DELEGATIONS=/etc/kbd/delegations
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/kbd", "health-check"]
ENTRYPOINT ["/kbd"]
