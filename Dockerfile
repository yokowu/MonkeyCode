FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

WORKDIR /src
ENV CGO_ENABLED=0

COPY go.work* ./
COPY backend ./backend
COPY socket.io-golang ./socket.io-golang
ARG GOMODCACHE
RUN --mount=type=cache,target=${GOMODCACHE} \
    GOPROXY=https://goproxy.cn,direct go mod download

ARG TARGETOS TARGETARCH GOCACHE
ARG VERSION
ARG BUILD_TIME
ARG GIT_COMMIT
RUN --mount=type=bind,target=. \
--mount=type=cache,target=${GOMODCACHE} \
--mount=type=cache,target=${GOCACHE} \
GOOS=$TARGETOS GOARCH=$TARGETARCH \
go build \
-ldflags "-w -s -X 'github.com/chaitin/MonkeyCode/backend/pkg/version.Version=${VERSION}' -X 'github.com/chaitin/MonkeyCode/backend/pkg/version.BuildTime=${BUILD_TIME}' -X 'github.com/chaitin/MonkeyCode/backend/pkg/version.GitCommit=${GIT_COMMIT}'" \
-o /out/main \
./backend/pro/cmd/server 

FROM alpine:3.22.1 as binary

WORKDIR /app

ADD backend/migration ./migration
ADD backend/assets/vsix ./assets/vsix

COPY --from=builder /out/main /app/main

CMD [ "./main" ]