// main.go
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/joho/godotenv"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

var (
	kmsClient   *kms.KeyManagementClient
	nameVersion string
)

func init() {
	// Carga .env si existe (para desarrollo local)
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  No se ha encontrado .env, usando vars de entorno")
	}

	// Inicializa el cliente de Cloud KMS
	ctx := context.Background()
	var err error
	kmsClient, err = kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatalf("kms.NewKeyManagementClient: %v", err)
	}

	// Construye el nombre completo de la CryptoKeyVersion
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID == "" {
		log.Fatal("❌ GOOGLE_CLOUD_PROJECT no está definido")
	}
	locationID := getEnv("KMS_LOCATION", "global")
	keyRingID := getEnv("KMS_KEY_RING", "EzeKeyRing")
	keyID := getEnv("KMS_KEY", "EzeKey")
	keyVersionID := getEnv("KMS_KEY_VERSION", "1")

	nameVersion = fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
		projectID, locationID, keyRingID, keyID, keyVersionID,
	)
}

func main() {
	http.HandleFunc("/sign", signHandler)
	http.HandleFunc("/verify", verifyHandler)

	port := getEnv("PORT", "8080")
	log.Printf("Listening on :%s …", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// signHandler acepta cualquier JSON, inyecta "timestamp" y lo firma
func signHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Sólo POST permitido"})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No se pudo leer el body"})
		return
	}
	var payloadMap map[string]interface{}
	if err := json.Unmarshal(body, &payloadMap); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON inválido"})
		return
	}

	// Inyectar timestamp UTC
	payloadMap["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)

	// Canonicalizar payload
	data, err := json.Marshal(payloadMap)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Error interno al serializar payload"})
		return
	}

	// Firmar con Cloud KMS
	ctx := context.Background()
	sigResp, err := kmsClient.MacSign(ctx, &kmspb.MacSignRequest{
		Name: nameVersion,
		Data: data,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Error firmando: %v", err)})
		return
	}

	signature := base64.StdEncoding.EncodeToString(sigResp.Mac)
	resp := map[string]interface{}{
		"payload":   payloadMap,
		"signature": signature,
	}
	writeJSON(w, http.StatusOK, resp)
}

// verifyHandler reconstruye CANÓNICAMENTE el payload y verifica la firma
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Sólo POST permitido"})
		return
	}

	// Definimos una request genérica
	var req struct {
		Payload   json.RawMessage `json:"payload"`
		Signature string          `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON inválido"})
		return
	}

	// 1) Volver a parsear el RawMessage en un objeto para canonicalizar:
	var obj interface{}
	if err := json.Unmarshal(req.Payload, &obj); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Payload inválido"})
		return
	}
	// 2) Serializar canónicamente (sin indentación, keys ordenadas):
	canonicalData, err := json.Marshal(obj)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Error interno al serializar payload"})
		return
	}
	// 3) Decodificar la firma Base64:
	mac, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Firma Base64 inválida"})
		return
	}
	// 4) Verificar con Cloud KMS
	ctx := context.Background()
	verifyResp, err := kmsClient.MacVerify(ctx, &kmspb.MacVerifyRequest{
		Name: nameVersion,
		Data: canonicalData,
		Mac:  mac,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Error verificando: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"valid": verifyResp.Success})
}

// writeJSON emite siempre JSON con el Content-Type adecuado
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
