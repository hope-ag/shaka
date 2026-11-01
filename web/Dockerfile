# Cloud Run image: Litestream restores the SQLite database from GCS when the container
# starts, runs the app as its child, and copies every write back to the bucket.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /shaka . && mkdir /data

FROM litestream/litestream:0.5.17-scratch
COPY --from=build /shaka /usr/local/bin/shaka
COPY --from=build --chown=65532:65532 /data /data
COPY litestream.yml /etc/litestream.yml
USER 65532
ENTRYPOINT ["/usr/local/bin/litestream", "replicate", "-restore-if-db-not-exists", "-exec", "/usr/local/bin/shaka -db /data/ca.db -ca /secrets/key/user_ca -addr :8080"]
