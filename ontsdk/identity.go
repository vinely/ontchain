package ontsdk

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	base58 "github.com/itchyny/base58-go"
	"github.com/ontio/ontology-crypto/keypair"
	s "github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology/core/types"
	"golang.org/x/crypto/ripemd160"
)

const (
	// SCHEME - did scheme
	SCHEME = "did"
	// METHOD - did method
	METHOD = "ont"
	// VER - did version
	VER = 0x41
)

// Controller -
type Controller struct {
	ID         string
	PrivateKey keypair.PrivateKey
	PublicKey  keypair.PublicKey
	SigScheme  s.SignatureScheme
}

// Sign -
func (c *Controller) Sign(data []byte) ([]byte, error) {
	sig, err := s.Sign(c.SigScheme, c.PrivateKey, data, nil)
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
func (c *Controller) GetPrivateKey() keypair.PrivateKey {
	return c.PrivateKey
}

// GetPublicKey -
func (c *Controller) GetPublicKey() keypair.PublicKey {
	return c.PublicKey
}

// GetSigScheme -
func (c *Controller) GetSigScheme() s.SignatureScheme {
	return c.SigScheme
}

// ControllerData -
type ControllerData struct {
	ID     string `json:"id"`
	Public string `json:"publicKey,omitemtpy"`
	SigSch string `json:"signatureScheme"`
	keypair.ProtectedKey
	scrypt *keypair.ScryptParam
}

// NewControllerData -
func NewControllerData(id string, keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte, scrypts ...*keypair.ScryptParam) (*ControllerData, error) {
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
	return NewControllerDataFromProtectedKey(id, hex.EncodeToString(keypair.SerializePublicKey(pubkey)), prvSecret, sigScheme.Name(), scrypt), nil
}

// NewControllerDataFromProtectedKey -
func NewControllerDataFromProtectedKey(id, pubKey string, protectedKey *keypair.ProtectedKey, SigSch string, scrypts ...*keypair.ScryptParam) *ControllerData {
	var scrypt *keypair.ScryptParam
	if len(scrypts) > 0 {
		scrypt = scrypts[0]
	} else {
		scrypt = keypair.GetScryptParameters()
	}
	ctrData := &ControllerData{
		ID:     id,
		Public: pubKey,
		scrypt: scrypt,
		SigSch: SigSch,
	}
	ctrData.SetKeyPair(protectedKey)
	return ctrData
}

// GetController -
func (c *ControllerData) GetController(passwd []byte) (*Controller, error) {
	privateKey, err := keypair.DecryptWithCustomScrypt(&c.ProtectedKey, passwd, c.scrypt)
	if err != nil {
		return nil, fmt.Errorf("decrypt privateKey error:%s", err)
	}
	publicKey := privateKey.Public()
	scheme, err := s.GetScheme(c.SigSch)
	if err != nil {
		return nil, fmt.Errorf("signature scheme error:%s", err)
	}
	return &Controller{
		ID:         c.ID,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		SigScheme:  scheme,
	}, nil
}

// SetKeyPair -
func (c *ControllerData) SetKeyPair(keyinfo *keypair.ProtectedKey) {
	c.Address = keyinfo.Address
	c.EncAlg = keyinfo.EncAlg
	c.Alg = keyinfo.Alg
	c.Hash = keyinfo.Hash
	c.Key = make([]byte, len(keyinfo.Key))
	copy(c.Key, keyinfo.Key)
	c.Param = keyinfo.Param
	c.Salt = make([]byte, len(keyinfo.Salt))
	copy(c.Salt, keyinfo.Salt)
}

// GetKeyPair -
func (c *ControllerData) GetKeyPair() *keypair.ProtectedKey {
	var keyinfo = new(keypair.ProtectedKey)
	keyinfo.Address = c.Address
	keyinfo.EncAlg = c.EncAlg
	keyinfo.Alg = c.Alg
	keyinfo.Hash = c.Hash
	keyinfo.Key = make([]byte, len(c.Key))
	copy(keyinfo.Key, c.Key)
	keyinfo.Param = c.Param
	keyinfo.Salt = make([]byte, len(c.Salt))
	copy(keyinfo.Salt, c.Salt)
	return keyinfo
}

// Clone -
func (c *ControllerData) Clone() *ControllerData {
	ctrData := &ControllerData{
		ID:     c.ID,
		Public: c.Public,
		scrypt: c.scrypt,
		SigSch: c.SigSch,
	}
	ctrData.SetKeyPair(c.GetKeyPair())
	return ctrData
}

// GetScrypt -
func (c *ControllerData) GetScrypt() *keypair.ScryptParam {
	return c.scrypt
}

// Identity -
type Identity struct {
	ID          string
	Label       string
	Lock        bool
	IsDefault   bool
	controllers []*ControllerData
	ctrsIDMap   map[string]*ControllerData
	ctrsPubMap  map[string]*ControllerData
	Extra       interface{}
	scrypt      *keypair.ScryptParam
}

// NewIdentity -
func NewIdentity(scrypt *keypair.ScryptParam) (*Identity, error) {
	id, err := GenerateID()
	if err != nil {
		return nil, err
	}
	identity := &Identity{
		ID:          id,
		scrypt:      scrypt,
		controllers: make([]*ControllerData, 0),
		ctrsIDMap:   make(map[string]*ControllerData),
		ctrsPubMap:  make(map[string]*ControllerData),
	}
	return identity, nil
}

// NewIdentityFromIdentityData -
func NewIdentityFromIdentityData(identityData *IdentityData) (*Identity, error) {
	identity := &Identity{
		ID:          identityData.ID,
		Label:       identityData.Label,
		Lock:        identityData.Lock,
		IsDefault:   identityData.IsDefault,
		controllers: make([]*ControllerData, 0, len(identityData.Control)),
		ctrsIDMap:   make(map[string]*ControllerData),
		ctrsPubMap:  make(map[string]*ControllerData),
		scrypt:      identityData.scrypt,
	}
	for _, ctrData := range identityData.Control {
		_, ok := identity.ctrsIDMap[ctrData.ID]
		if ok {
			return nil, fmt.Errorf("duplicate controller id:%s", ctrData.ID)
		}
		_, ok = identity.ctrsPubMap[ctrData.Public]
		if ok {
			return nil, fmt.Errorf("duplicate controller pubkey:%s", ctrData.Public)
		}
		identity.ctrsIDMap[ctrData.ID] = ctrData
		identity.ctrsPubMap[ctrData.Public] = ctrData
		identity.controllers = append(identity.controllers, ctrData)
	}
	return identity, nil
}

// NewController -
func (i *Identity) NewController(id string, keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte) (*Controller, error) {
	controllerData, err := NewControllerData(id, keyType, curveCode, sigScheme, passwd)
	if err != nil {
		return nil, err
	}
	err = i.AddControllerData(controllerData)
	if err != nil {
		return nil, err
	}
	return controllerData.GetController(passwd)
}

// NewDefaultSettingController -
func (i *Identity) NewDefaultSettingController(id string, passwd []byte) (*Controller, error) {
	return i.NewController(id, keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, passwd)
}

// AddControllerData -
func (i *Identity) AddControllerData(controllerData *ControllerData) error {
	if !ScryptEqual(controllerData.scrypt, i.scrypt) {
		return fmt.Errorf("scrypt unmatch")
	}
	if controllerData.ID == "" {
		return fmt.Errorf("controller id cannot empty string")
	}
	_, ok := i.ctrsIDMap[controllerData.ID]
	if ok {
		return fmt.Errorf("duplicate controller id:%s", controllerData.ID)
	}
	_, ok = i.ctrsPubMap[controllerData.Public]
	if ok {
		return fmt.Errorf("duplicate controller pubkey:%s", controllerData.Public)
	}
	i.controllers = append(i.controllers, controllerData)
	i.ctrsIDMap[controllerData.ID] = controllerData
	i.ctrsPubMap[controllerData.Public] = controllerData
	return nil
}

// DeleteControllerData -
func (i *Identity) DeleteControllerData(id string) error {
	ctrData, ok := i.ctrsIDMap[id]
	if !ok {
		return ErrControllerNotFound
	}
	size := len(i.controllers)
	for index, ctrData := range i.controllers {
		if ctrData.ID != id {
			continue
		}
		if size-1 == index {
			i.controllers = i.controllers[:index]
		} else {
			i.controllers = append(i.controllers[:index], i.controllers[index+1:]...)
		}
	}
	delete(i.ctrsIDMap, id)
	delete(i.ctrsPubMap, ctrData.Public)
	return nil
}

// GetControllerDataByID -
func (i *Identity) GetControllerDataByID(id string) (*ControllerData, error) {
	ctrData, ok := i.ctrsIDMap[id]
	if !ok {
		return nil, ErrControllerNotFound
	}
	return ctrData.Clone(), nil
}

// GetControllerDataByPubKey -
func (i *Identity) GetControllerDataByPubKey(pubKey string) (*ControllerData, error) {
	ctrData, ok := i.ctrsPubMap[pubKey]
	if !ok {
		return nil, ErrControllerNotFound
	}
	return ctrData.Clone(), nil
}

// GetControllerDataByIndex -
func (i *Identity) GetControllerDataByIndex(index int) (*ControllerData, error) {
	if index <= 0 || index > len(i.controllers) {
		return nil, fmt.Errorf("index out of range")
	}
	return i.controllers[index-1].Clone(), nil
}

//ControllerCount -
func (i *Identity) ControllerCount() int {
	return len(i.controllers)
}

// GetControllerByID -
func (i *Identity) GetControllerByID(id string, passwd []byte) (*Controller, error) {
	ctrData, err := i.GetControllerDataByID(id)
	if err != nil {
		return nil, err
	}
	return ctrData.GetController(passwd)
}

// GetControllerByPubKey -
func (i *Identity) GetControllerByPubKey(pubKey string, passwd []byte) (*Controller, error) {
	ctrData, err := i.GetControllerDataByPubKey(pubKey)
	if err != nil {
		return nil, err
	}
	return ctrData.GetController(passwd)
}

// GetControllerByIndex -
func (i *Identity) GetControllerByIndex(index int, passwd []byte) (*Controller, error) {
	ctrData, err := i.GetControllerDataByIndex(index)
	if err != nil {
		return nil, err
	}
	return ctrData.GetController(passwd)
}

// ToIdentityData -
func (i *Identity) ToIdentityData() *IdentityData {
	identityData := &IdentityData{
		ID:      i.ID,
		Label:   i.Label,
		Lock:    i.Lock,
		Extra:   i.Extra,
		Control: make([]*ControllerData, 0, len(i.controllers)),
	}
	for _, ctr := range i.controllers {
		identityData.Control = append(identityData.Control, ctr.Clone())
	}
	return identityData
}

// IdentityData -
type IdentityData struct {
	ID        string            `json:"ontid"`
	Label     string            `json:"label,omitempty"`
	Lock      bool              `json:"lock"`
	IsDefault bool              `json:"isDefault"`
	Control   []*ControllerData `json:"controls,omitempty"`
	Extra     interface{}       `json:"extra,omitempty"`
	scrypt    *keypair.ScryptParam
}

// GenerateID -
func GenerateID() (string, error) {
	var buf [32]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return "", fmt.Errorf("generate ID error, %s", err)
	}
	return CreateID(buf[:])
}

// CreateID -
func CreateID(nonce []byte) (string, error) {
	hasher := ripemd160.New()
	_, err := hasher.Write(nonce)
	if err != nil {
		return "", fmt.Errorf("create ID error, %s", err)
	}
	data := hasher.Sum([]byte{VER})
	data = append(data, checksum(data)...)

	bi := new(big.Int).SetBytes(data).String()
	idstring, err := base58.BitcoinEncoding.Encode([]byte(bi))
	if err != nil {
		return "", fmt.Errorf("create ID error, %s", err)
	}

	return SCHEME + ":" + METHOD + ":" + string(idstring), nil
}

// VerifyID -
func VerifyID(id string) bool {
	if len(id) < 9 {
		return false
	}
	if id[0:8] != "did:ont:" {
		return false
	}
	buf, err := base58.BitcoinEncoding.Decode([]byte(id[8:]))
	if err != nil {
		return false
	}
	bi, ok := new(big.Int).SetString(string(buf), 10)
	if !ok || bi == nil {
		return false
	}
	buf = bi.Bytes()
	// 1 byte version + 20 byte hash + 4 byte checksum
	if len(buf) != 25 {
		return false
	}
	pos := len(buf) - 4
	data := buf[:pos]
	check := buf[pos:]
	sum := checksum(data)
	if !bytes.Equal(sum, check) {
		return false
	}
	return true
}

func checksum(data []byte) []byte {
	sum := sha256.Sum256(data)
	sum = sha256.Sum256(sum[:])
	return sum[:4]
}

const (
	// KeyStatusRevoke -
	KeyStatusRevoke = "revoked"
	// KyeStatusInUse -
	KyeStatusInUse = "in use"
)

// DDOOwner -
type DDOOwner struct {
	pubKeyIndex uint32
	PubKeyID    string
	Type        string
	Curve       string
	Value       string
}

// GetIndex -
func (d *DDOOwner) GetIndex() uint32 {
	return d.pubKeyIndex
}

// DDOAttribute -
type DDOAttribute struct {
	Key       []byte
	ValueType []byte
	Value     []byte
}

// DDO -
type DDO struct {
	OntID      string
	Owners     []*DDOOwner
	Attributes []*DDOAttribute
	Recovery   string
}
