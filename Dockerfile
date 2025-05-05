# 1) Etapa builder: descarga deps y compila el binario
FROM golang:1.20 AS builder
WORKDIR /app

# Copia primero sólo los ficheros de módulos
COPY go.mod go.sum ./
# Ahora sí, descarga las dependencias
RUN go mod download

# Copia todo el código y compílalo
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server .

# 2) Imagen final muy ligera
FROM gcr.io/distroless/base-debian10
COPY --from=builder /app/server /server
EXPOSE 8080
ENTRYPOINT ["/server"]