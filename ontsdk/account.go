package ontsdk

import (
	"encoding/hex"
	"fmt"

	"github.com/ontio/ontology-crypto/keypair"
	s "github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
)

// Signer -
type Signer interface {
	Sign(data []byte) ([]byte, error)
	GetPublicKey() keypair.PublicKey
	GetPrivateKey() keypair.PrivateKey
	GetSigScheme() s.SignatureScheme
}

// Account - crypto object
type Account struct {
	PrivateKey keypair.PrivateKey
	PublicKey  keypair.PublicKey
	Address    common.Address
	SigScheme  s.SignatureScheme
}

// NewAccount -
func NewAccount(sigscheme ...s.SignatureScheme) *Account {
	var scheme s.SignatureScheme
	if len(sigscheme) == 0 {
		scheme = s.SHA256withECDSA
	} else {
		scheme = sigscheme[0]
	}
	var pkAlgorithm keypair.KeyType
	var params interface{}
	switch scheme {
	case s.SHA224withECDSA, s.SHA3_224withECDSA:
		pkAlgorithm = keypair.PK_ECDSA
		params = keypair.P224
	case s.SHA256withECDSA, s.SHA3_256withECDSA, s.RIPEMD160withECDSA:
		pkAlgorithm = keypair.PK_ECDSA
		params = keypair.P256
	case s.SHA384withECDSA, s.SHA3_384withECDSA:
		pkAlgorithm = keypair.PK_ECDSA
		params = keypair.P384
	case s.SHA512withECDSA, s.SHA3_512withECDSA:
		pkAlgorithm = keypair.PK_ECDSA
		params = keypair.P521
	case s.SM3withSM2:
		pkAlgorithm = keypair.PK_SM2
		params = keypair.SM2P256V1
	case s.SHA512withEDDSA:
		pkAlgorithm = keypair.PK_EDDSA
		params = keypair.ED25519
	default:
		return nil
	}
	pri, pub, _ := keypair.GenerateKeyPair(pkAlgorithm, params)
	address := types.AddressFromPubKey(pub)
	return &Account{
		PrivateKey: pri,
		PublicKey:  pub,
		Address:    address,
		SigScheme:  scheme,
	}
}

// Sign -
func (a *Account) Sign(data []byte) ([]byte, error) {
	sig, err := s.Sign(a.SigScheme, a.PrivateKey, data, nil)
	if err != nil {
		return nil, err
	}
	sigData, err := s.Serialize(sig)
	if err != nil {
		return nil, fmt.Errorf("signature.Serialize error:%s", err)
	}
	return sigData, nil
}

// GetPrivateKey -
func (a *Account) GetPrivateKey() keypair.PrivateKey {
	return a.PrivateKey
}

// GetPublicKey -
func (a *Account) GetPublicKey() keypair.PublicKey {
	return a.PublicKey
}

// GetSigScheme -
func (a *Account) GetSigScheme() s.SignatureScheme {
	return a.SigScheme
}

// AccountData - for wallet read and save, no crypto object included
type AccountData struct {
	keypair.ProtectedKey

	Label     string `json:"label"`
	PubKey    string `json:"publicKey"`
	SigSch    string `json:"signatureScheme"`
	IsDefault bool   `json:"isDefault"`
	Lock      bool   `json:"lock"`
	scrypt    *keypair.ScryptParam
}

// NewAccountData -
func NewAccountData(keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte, scrypts ...*keypair.ScryptParam) (*AccountData, error) {
	if len(passwd) == 0 {
		return nil, fmt.Errorf("password cannot empty")
	}
	if !CheckKeyTypeCurve(keyType, curveCode) {
		return nil, fmt.Errorf("curve unmath key type")
	}
	if !CheckSigScheme(keyType, sigScheme) {
		return nil, fmt.Errorf("sigScheme:%s does not match with KeyType:%s", sigScheme.Name(), GetKeyTypeString(keyType))
	}
	var scrypt *keypair.ScryptParam
	if len(scrypts) > 0 {
		scrypt = scrypts[0]
	} else {
		scrypt = keypair.GetScryptParameters()
	}
	prvkey, pubkey, err := keypair.GenerateKeyPair(keyType, curveCode)
	if err != nil {
		return nil, fmt.Errorf("generateKeyPair error:%s", err)
	}
	address := types.AddressFromPubKey(pubkey)
	addressBase58 := address.ToBase58()
	prvSecret, err := keypair.EncryptWithCustomScrypt(prvkey, addressBase58, passwd, scrypt)
	if err != nil {
		return nil, fmt.Errorf("encryptPrivateKey error:%s", err)
	}
	accData := &AccountData{}
	accData.SetKeyPair(prvSecret)
	accData.SigSch = sigScheme.Name()
	accData.PubKey = hex.EncodeToString(keypair.SerializePublicKey(pubkey))
	accData.scrypt = scrypt
	return accData, nil
}

// GetAccount -
func (a *AccountData) GetAccount(passwd []byte) (*Account, error) {
	privateKey, err := keypair.DecryptWithCustomScrypt(&a.ProtectedKey, passwd, a.scrypt)
	if err != nil {
		return nil, fmt.Errorf("decrypt privateKey error:%s", err)
	}
	publicKey := privateKey.Public()
	addr := types.AddressFromPubKey(publicKey)
	scheme, err := s.GetScheme(a.SigSch)
	if err != nil {
		return nil, fmt.Errorf("signature scheme error:%s", err)
	}
	return &Account{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    addr,
		SigScheme:  scheme,
	}, nil
}

// GetScrypt -
func (a *AccountData) GetScrypt() *keypair.ScryptParam {
	return a.scrypt
}

// Clone -
func (a *AccountData) Clone() *AccountData {
	accData := &AccountData{
		Label:     a.Label,
		PubKey:    a.PubKey,
		SigSch:    a.SigSch,
		IsDefault: a.IsDefault,
		Lock:      a.Lock,
		scrypt:    a.scrypt,
	}
	accData.SetKeyPair(a.GetKeyPair())
	return accData
}

// SetKeyPair -
func (a *AccountData) SetKeyPair(keyinfo *keypair.ProtectedKey) {
	a.Address = keyinfo.Address
	a.EncAlg = keyinfo.EncAlg
	a.Alg = keyinfo.Alg
	a.Hash = keyinfo.Hash
	a.Key = make([]byte, len(keyinfo.Key))
	copy(a.Key, keyinfo.Key)
	a.Param = keyinfo.Param
	a.Salt = make([]byte, len(keyinfo.Salt))
	copy(a.Salt, keyinfo.Salt)
}

// GetKeyPair -
func (a *AccountData) GetKeyPair() *keypair.ProtectedKey {
	var keyinfo = new(keypair.ProtectedKey)
	keyinfo.Address = a.Address
	keyinfo.EncAlg = a.EncAlg
	keyinfo.Alg = a.Alg
	keyinfo.Hash = a.Hash
	keyinfo.Key = make([]byte, len(a.Key))
	copy(keyinfo.Key, a.Key)
	keyinfo.Param = a.Param
	keyinfo.Salt = make([]byte, len(a.Salt))
	copy(keyinfo.Salt, a.Salt)
	return keyinfo
}

// GetKeyTypeString -
func GetKeyTypeString(keyType keypair.KeyType) string {
	switch keyType {
	case keypair.PK_ECDSA:
		return "ECDSA"
	case keypair.PK_SM2:
		return "SM2"
	case keypair.PK_EDDSA:
		return "Ed25519"
	default:
		return "unknown key type"
	}
}

// CheckKeyTypeCurve -
func CheckKeyTypeCurve(keyType keypair.KeyType, curveCode byte) bool {
	switch keyType {
	case keypair.PK_ECDSA:
		switch curveCode {
		case keypair.P224:
		case keypair.P256:
		case keypair.P384:
		case keypair.P521:
		default:
			return false
		}
	case keypair.PK_SM2:
		switch curveCode {
		case keypair.SM2P256V1:
		default:
			return false
		}
	case keypair.PK_EDDSA:
		switch curveCode {
		case keypair.ED25519:
		default:
			return false
		}
	}
	return true
}

// CheckSigScheme -
func CheckSigScheme(keyType keypair.KeyType, sigScheme s.SignatureScheme) bool {
	switch keyType {
	case keypair.PK_ECDSA:
		switch sigScheme {
		case s.SHA224withECDSA:
		case s.SHA256withECDSA:
		case s.SHA384withECDSA:
		case s.SHA512withECDSA:
		case s.SHA3_224withECDSA:
		case s.SHA3_256withECDSA:
		case s.SHA3_384withECDSA:
		case s.SHA3_512withECDSA:
		case s.RIPEMD160withECDSA:
		default:
			return false
		}
	case keypair.PK_SM2:
		switch sigScheme {
		case s.SM3withSM2:
		default:
			return false
		}
	case keypair.PK_EDDSA:
		switch sigScheme {
		case s.SHA512withEDDSA:
		default:
			return false
		}
	default:
		return false
	}
	return true
}

// GetCurveName -
func GetCurveName(pubKey []byte) string {
	if len(pubKey) < 2 {
		return ""
	}
	switch keypair.KeyType(pubKey[0]) {
	case keypair.PK_ECDSA, keypair.PK_SM2:
		c, err := keypair.GetCurve(pubKey[1])
		if err != nil {
			return ""
		}
		return c.Params().Name
	case keypair.PK_EDDSA:
		if pubKey[1] == keypair.ED25519 {
			return "ed25519"
		}
		return ""

	default:
		return ""
	}
}
