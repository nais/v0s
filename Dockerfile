FROM golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY api ./api
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/v0s ./cmd/v0s
RUN mkdir -p /out/cache/home /out/tmp

FROM scratch
ENV HOME=/var/cache/v0s/home
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/v0s /v0s
COPY --from=build --chown=65532:65532 /out/cache /var/cache/v0s
COPY --from=build --chmod=1777 /out/tmp /tmp
USER 65532:65532
ENTRYPOINT ["/v0s"]
