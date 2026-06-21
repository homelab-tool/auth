package auth

import (
	"crypto"
	"database/sql"
	"encoding/json"

	"github.com/bytemare/ksf"
	"github.com/bytemare/opaque"
	"github.com/rs/zerolog/log"
)

type Argon2Params struct {
	Iterations  uint32 `json:"iterations"`
	Memory      uint32 `json:"memory"`
	Parallelism uint8  `json:"parallelism"`
}

type KSFSettings struct {
	Algorithm Argon2Params
	Salt      []byte
	OutputLen int
}

func (k *KSFSettings) AlgorithmName() string { return "argon2id" }

func (k *KSFSettings) ParamsJSON() (string, error) {
	b, err := json.Marshal(k.Algorithm)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (k *KSFSettings) ClientOptions() *opaque.ClientOptions {
	return &opaque.ClientOptions{
		KSFSalt:       k.Salt,
		KSFLength:     k.OutputLen,
		KSFParameters: []uint64{uint64(k.Algorithm.Iterations), uint64(k.Algorithm.Memory), uint64(k.Algorithm.Parallelism)},
	}
}

func (k *KSFSettings) Identifier() ksf.Identifier {
	return ksf.Argon2id
}

// DefaultKSF returns the default KSF settings.
//
// The salt is a zero-byte array to match the opaque-ke WASM library's
// hardcoded default (&[0; argon2::RECOMMENDED_SALT_LEN]) for protocol
// compatibility. Per RFC 9807 §10.11, precomputation resistance is
// provided by the OPRF key (opaque_skm), not the KSF salt, so a
// static salt is acceptable here.
func DefaultKSF() *KSFSettings {
	return &KSFSettings{
		Algorithm: Argon2Params{
			Iterations:  3,
			Memory:      65536,
			Parallelism: 4,
		},
		Salt:      make([]byte, 16),
		OutputLen: 64,
	}
}

// ServerConfig returns the OPAQUE configuration. Clients receive their KSF
// settings from the server at registration time (see DefaultKSF), so the
// configuration below just identifies the KSF algorithm — the actual
// parameters go through ClientOptions in RegistrationFinalize/GenerateKE3.
func ServerConfig() *opaque.Configuration {
	return &opaque.Configuration{
		OPRF:    opaque.RistrettoSha512,
		AKE:     opaque.RistrettoSha512,
		KSF:     DefaultKSF().Identifier(),
		KDF:     crypto.SHA512,
		MAC:     crypto.SHA512,
		Hash:    crypto.SHA512,
		Context: nil,
	}
}

func CreateOpaqueServer(db *sql.DB) (*opaque.Server, error) {
	var conf = ServerConfig()

	server, err := conf.Server()
	if err != nil {
		log.Err(err).Msg("failed to create opaque server")
		return nil, err
	}

	skm, err := loadKeyMaterial(db, conf)
	if err != nil {
		log.Err(err).Msg("failed to load opaque key material")
		return nil, err
	}

	if err = server.SetKeyMaterial(skm); err != nil {
		log.Err(err).Msg("failed to set opaque key material")
		return nil, err
	}

	return server, nil
}

const nameKeyMaterial = "opaque_skm"

func loadKeyMaterial(db *sql.DB, conf *opaque.Configuration) (*opaque.ServerKeyMaterial, error) {
	var bytes []byte
	var err = db.QueryRow("SELECT value FROM secrets WHERE name = ?", nameKeyMaterial).Scan(&bytes)
	if err == nil {
		return conf.DecodeServerKeyMaterial(bytes)
	}

	log.Info().Msg("no previous opaque key material found, generating new secrets")
	var seed = conf.GenerateOPRFSeed()
	var privateKey, publicKey = conf.KeyGen()

	var skm = &opaque.ServerKeyMaterial{
		Identity:       publicKey.Encode(),
		PrivateKey:     privateKey,
		PublicKeyBytes: publicKey.Encode(),
		OPRFGlobalSeed: seed,
	}

	bytes = skm.Encode()
	if _, err = db.Exec("INSERT INTO secrets (name, value) VALUES (?, ?)", nameKeyMaterial, bytes); err != nil {
		return nil, err
	}

	// Read back and decode to verify the round-trip works, matching restart behavior.
	err = db.QueryRow("SELECT value FROM secrets WHERE name = ?", nameKeyMaterial).Scan(&bytes)
	if err != nil {
		return nil, err
	}

	return conf.DecodeServerKeyMaterial(bytes)
}
