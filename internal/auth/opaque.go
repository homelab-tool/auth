package auth

import (
	"crypto"
	"database/sql"

	"github.com/bytemare/ksf"
	"github.com/bytemare/opaque"
	"github.com/rs/zerolog/log"
)

func ServerConfig() *opaque.Configuration {
	return &opaque.Configuration{
		OPRF:    opaque.RistrettoSha512,
		AKE:     opaque.RistrettoSha512,
		KSF:     ksf.Argon2id,
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

const (
	name_key_material = "opaque_skm"
)

func loadKeyMaterial(db *sql.DB, conf *opaque.Configuration) (*opaque.ServerKeyMaterial, error) {
	var bytes []byte
	var err = db.QueryRow("SELECT value FROM secrets WHERE name = ?", name_key_material).Scan(&bytes)
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
	if _, err = db.Exec("INSERT INTO secrets (name, value) VALUES (?, ?)", name_key_material, bytes); err != nil {
		return nil, err
	}

	// Read back and decode to verify the round-trip works, matching restart behavior.
	err = db.QueryRow("SELECT value FROM secrets WHERE name = ?", name_key_material).Scan(&bytes)
	if err != nil {
		return nil, err
	}

	return conf.DecodeServerKeyMaterial(bytes)
}
