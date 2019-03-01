package ontsdk

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/ontio/ontology-crypto/keypair"
	s "github.com/ontio/ontology-crypto/signature"
	sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
)

// DefaultWalletName -
var DefaultWalletName = "MyWallet"

// DefaultWalletVersion -
var DefaultWalletVersion = "1.1"

// ErrAccountNotFound -
var ErrAccountNotFound = errors.New("account not found")

// ErrIdentityNotFound -
var ErrIdentityNotFound = errors.New("identity not found")

// ErrControllerNotFound -
var ErrControllerNotFound = errors.New("controller not found")

// Wallet -
type Wallet struct {
	Name             string
	Version          string
	Scrypt           *keypair.ScryptParam
	Extra            string
	accounts         []*AccountData
	identities       []*Identity
	defAcc           *AccountData
	accAddressMap    map[string]*AccountData
	accLabelMap      map[string]*AccountData
	identityMap      map[string]*Identity
	identityLabelMap map[string]*Identity
	defIdentity      *Identity
	path             string
	ontSdk           *sdk.OntologySdk
	lock             sync.RWMutex
}

// NewWallet -
func NewWallet(path string) *Wallet {
	return &Wallet{
		Name:             DefaultWalletName,
		Version:          DefaultWalletVersion,
		Scrypt:           keypair.GetScryptParameters(),
		accounts:         make([]*AccountData, 0),
		accAddressMap:    make(map[string]*AccountData),
		accLabelMap:      make(map[string]*AccountData),
		identities:       make([]*Identity, 0),
		identityMap:      make(map[string]*Identity),
		identityLabelMap: make(map[string]*Identity),
		path:             path,
	}
}

// GetWalletData - get walletdata from wallets
func (w *Wallet) GetWalletData() WalletData {
	w.lock.RLock()
	walletData := WalletData{
		Name:       w.Name,
		Version:    w.Version,
		Scrypt:     w.Scrypt,
		Identities: make([]*IdentityData, 0),
		Accounts:   make([]*AccountData, 0),
		Extra:      w.Extra,
	}
	for _, identity := range w.identities {
		walletData.Identities = append(walletData.Identities, identity.ToIdentityData())
	}
	for _, acc := range w.accounts {
		walletData.Accounts = append(walletData.Accounts, acc)
	}
	w.lock.RUnlock()
	return walletData
}

// LoadWalletFromData - Load walletData to wallet
func LoadWalletFromData(wd WalletData, path string) (*Wallet, error) {
	wallet := NewWallet(path)
	wallet.Name = wd.Name
	wallet.Version = wd.Version
	wallet.Scrypt = wd.Scrypt
	wallet.Extra = wd.Extra
	for _, accountData := range wd.Accounts {
		accountData.scrypt = wallet.Scrypt
		if accountData.IsDefault {
			if wallet.defAcc != nil {
				return nil, fmt.Errorf("more than one default account")
			}
			wallet.defAcc = accountData
		}
		wallet.accounts = append(wallet.accounts, accountData)
		wallet.accAddressMap[accountData.Address] = accountData
		if accountData.Label != "" {
			_, ok := wallet.accLabelMap[accountData.Label]
			if ok {
				return nil, fmt.Errorf("duplicate account label:%s", accountData.Label)
			}
			wallet.accLabelMap[accountData.Label] = accountData
		}
	}
	if wallet.defAcc == nil && len(wd.Accounts) > 0 {
		wallet.defAcc = wd.Accounts[0]
	}

	for _, identityData := range wd.Identities {
		identityData.scrypt = wallet.Scrypt
		identity, err := NewIdentityFromIdentityData(identityData)
		if err != nil {
			return nil, fmt.Errorf("NewIdentityFromIdentityData error:%s", err)
		}
		if identity.IsDefault {
			if wallet.defIdentity != nil {
				return nil, fmt.Errorf("more than one default identity")
			}
			wallet.defIdentity = identity
		}
		wallet.identities = append(wallet.identities, identity)
		wallet.identityMap[identity.ID] = identity
		if identity.Label != "" {
			_, ok := wallet.identityLabelMap[identity.Label]
			if ok {
				return nil, fmt.Errorf("duplicate identity label:%s", identity.Label)
			}
			wallet.identityLabelMap[identity.Label] = identity
		}
	}
	if wallet.defIdentity == nil && len(wallet.identities) > 0 {
		wallet.defIdentity = wallet.identities[0]
	}
	return wallet, nil
}

// OpenWallet - open wallet from file on path. Create it if not existed.
func OpenWallet(path string) (*Wallet, error) {
	walletData := &WalletData{}
	err := walletData.Load(path)
	if err != nil {
		return nil, err
	}
	wallet := NewWallet(path)
	wallet.Name = walletData.Name
	wallet.Version = walletData.Version
	wallet.Scrypt = walletData.Scrypt
	wallet.Extra = walletData.Extra
	for _, accountData := range walletData.Accounts {
		accountData.scrypt = wallet.Scrypt
		if accountData.IsDefault {
			if wallet.defAcc != nil {
				return nil, fmt.Errorf("more than one default account")
			}
			wallet.defAcc = accountData
		}
		wallet.accounts = append(wallet.accounts, accountData)
		wallet.accAddressMap[accountData.Address] = accountData
		if accountData.Label != "" {
			_, ok := wallet.accLabelMap[accountData.Label]
			if ok {
				return nil, fmt.Errorf("duplicate account label:%s", accountData.Label)
			}
			wallet.accLabelMap[accountData.Label] = accountData
		}
	}
	if wallet.defAcc == nil && len(walletData.Accounts) > 0 {
		wallet.defAcc = walletData.Accounts[0]
	}

	for _, identityData := range walletData.Identities {
		identityData.scrypt = wallet.Scrypt
		identity, err := NewIdentityFromIdentityData(identityData)
		if err != nil {
			return nil, fmt.Errorf("NewIdentityFromIdentityData error:%s", err)
		}
		if identity.IsDefault {
			if wallet.defIdentity != nil {
				return nil, fmt.Errorf("more than one default identity")
			}
			wallet.defIdentity = identity
		}
		wallet.identities = append(wallet.identities, identity)
		wallet.identityMap[identity.ID] = identity
		if identity.Label != "" {
			_, ok := wallet.identityLabelMap[identity.Label]
			if ok {
				return nil, fmt.Errorf("duplicate identity label:%s", identity.Label)
			}
			wallet.identityLabelMap[identity.Label] = identity
		}
	}
	if wallet.defIdentity == nil && len(wallet.identities) > 0 {
		wallet.defIdentity = wallet.identities[0]
	}
	return wallet, nil
}

// NewAccount -
func (w *Wallet) NewAccount(keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte) (*Account, error) {
	accData, err := NewAccountData(keyType, curveCode, sigScheme, passwd, w.Scrypt)
	if err != nil {
		return nil, err
	}
	err = w.AddAccountData(accData)
	if err != nil {
		return nil, err
	}
	return accData.GetAccount(passwd)
}

// NewDefaultSettingAccount -
func (w *Wallet) NewDefaultSettingAccount(passwd []byte) (*Account, error) {
	return w.NewAccount(keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, passwd)
}

// NewAccountFromWIF -
func (w *Wallet) NewAccountFromWIF(wif, passwd []byte) (*Account, error) {
	if len(passwd) == 0 {
		return nil, fmt.Errorf("password cannot empty")
	}
	prvkey, err := keypair.GetP256KeyPairFromWIF(wif)
	if err != nil {
		return nil, fmt.Errorf("GetP256KeyPairFromWIF error:%s", err)
	}
	pubKey := prvkey.Public()
	address := types.AddressFromPubKey(pubKey)
	addressBase58 := address.ToBase58()
	prvSecret, err := keypair.EncryptWithCustomScrypt(prvkey, addressBase58, passwd, w.Scrypt)
	if err != nil {
		return nil, fmt.Errorf("encryptPrivateKey error:%s", err)
	}
	accData := &AccountData{}
	accData.SetKeyPair(prvSecret)
	accData.SigSch = s.SHA256withECDSA.Name()
	accData.PubKey = hex.EncodeToString(keypair.SerializePublicKey(pubKey))
	err = w.AddAccountData(accData)
	if err != nil {
		return nil, err
	}
	return &Account{
		PrivateKey: prvkey,
		PublicKey:  pubKey,
		Address:    address,
		SigScheme:  s.SHA256withECDSA,
	}, nil
}

// AddAccountData -
func (w *Wallet) AddAccountData(accountData *AccountData) error {
	if !ScryptEqual(accountData.scrypt, w.Scrypt) {
		return fmt.Errorf("scrypt unmatch")
	}
	w.lock.Lock()
	defer w.lock.Unlock()
	_, ok := w.accAddressMap[accountData.Address]
	if ok {
		return nil
	}
	if w.defAcc != nil && accountData.IsDefault {
		return fmt.Errorf("already have default account")
	}
	if accountData.Label != "" {
		_, ok := w.accLabelMap[accountData.Label]
		if ok {
			return fmt.Errorf("duplicate account label:%s", accountData.Label)
		}
		w.accLabelMap[accountData.Label] = accountData
	}
	if len(w.accounts) == 0 {
		accountData.IsDefault = true
	}
	if w.defAcc == nil {
		accountData.IsDefault = true
		w.defAcc = accountData
	}
	w.accAddressMap[accountData.Address] = accountData
	w.accounts = append(w.accounts, accountData)
	return nil
}

// DeleteAccount -
func (w *Wallet) DeleteAccount(address string) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	accData, ok := w.accAddressMap[address]
	if !ok {
		return ErrAccountNotFound
	}
	if accData.IsDefault {
		return fmt.Errorf("cannot delete default account")
	}
	delete(w.accAddressMap, address)
	if accData.Label != "" {
		delete(w.accLabelMap, accData.Label)
	}
	size := len(w.accounts)
	for index, accountData := range w.accounts {
		if accData.Address != accountData.Address {
			continue
		}
		if size-1 == index {
			w.accounts = w.accounts[:index]
		} else {
			w.accounts = append(w.accounts[:index], w.accounts[index+1:]...)
		}
		break
	}
	return nil
}

// SetDefaultAccount -
func (w *Wallet) SetDefaultAccount(address string) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	accData, ok := w.accAddressMap[address]
	if !ok {
		return ErrAccountNotFound
	}
	if w.defAcc != nil {
		w.defAcc.IsDefault = false
	}
	accData.IsDefault = true
	w.defAcc = accData
	return nil
}

// GetDefaultAccount -
func (w *Wallet) GetDefaultAccount(passwd []byte) (*Account, error) {
	w.lock.RLock()
	defer w.lock.RUnlock()
	if w.defAcc == nil {
		return nil, fmt.Errorf("does not set default account")
	}
	return w.defAcc.GetAccount(passwd)
}

// GetAccountByAddress -
func (w *Wallet) GetAccountByAddress(address string, passwd []byte) (*Account, error) {
	accData, err := w.GetAccountDataByAddress(address)
	if err != nil {
		return nil, err
	}
	return accData.GetAccount(passwd)
}

// GetAccountByLabel -
func (w *Wallet) GetAccountByLabel(label string, passwd []byte) (*Account, error) {
	accData, err := w.GetAccountDataByLabel(label)
	if err != nil {
		return nil, err
	}
	return accData.GetAccount(passwd)
}

// GetAccountByIndex -
// Index start from 1
func (w *Wallet) GetAccountByIndex(index int, passwd []byte) (*Account, error) {
	accData, err := w.GetAccountDataByIndex(index)
	if err != nil {
		return nil, err
	}
	return accData.GetAccount(passwd)
}

// GetAccountCount -
func (w *Wallet) GetAccountCount() int {
	w.lock.RLock()
	defer w.lock.RUnlock()
	return len(w.accounts)
}

// GetDefaultAccountData -
func (w *Wallet) GetDefaultAccountData() (*AccountData, error) {
	w.lock.RLock()
	defer w.lock.RUnlock()
	if w.defAcc == nil {
		return nil, fmt.Errorf("does not set default account")
	}
	return w.defAcc.Clone(), nil
}

// GetAccountDataByAddress -
func (w *Wallet) GetAccountDataByAddress(address string) (*AccountData, error) {
	w.lock.RLock()
	defer w.lock.RUnlock()
	accData, ok := w.accAddressMap[address]
	if !ok {
		return nil, ErrAccountNotFound
	}
	return accData.Clone(), nil
}

// GetAccountDataByLabel -
func (w *Wallet) GetAccountDataByLabel(label string) (*AccountData, error) {
	if label == "" {
		return nil, fmt.Errorf("cannot found account by empty label")
	}
	accData, ok := w.accLabelMap[label]
	if !ok {
		return nil, ErrAccountNotFound
	}
	return accData.Clone(), nil
}

// GetAccountDataByIndex -
// Index start from 1
func (w *Wallet) GetAccountDataByIndex(index int) (*AccountData, error) {
	w.lock.RLock()
	defer w.lock.RUnlock()
	if index <= 0 || index > len(w.accounts) {
		return nil, fmt.Errorf("index out of range")
	}
	accData := w.accounts[index-1]
	return accData.Clone(), nil
}

// SetLabel -
func (w *Wallet) SetLabel(address, newLabel string) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	accData, ok := w.accAddressMap[address]
	if !ok {
		return ErrAccountNotFound
	}
	if accData.Label == newLabel {
		return nil
	}
	if newLabel == "" {
		delete(w.accLabelMap, accData.Label)
		accData.Label = ""
		return nil
	}
	_, ok = w.accLabelMap[newLabel]
	if ok {
		return fmt.Errorf("duplicate label")
	}
	accData.Label = newLabel
	w.accLabelMap[newLabel] = accData
	return nil
}

// SetSigScheme -
func (w *Wallet) SetSigScheme(address string, sigScheme s.SignatureScheme) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	accData, ok := w.accAddressMap[address]
	if !ok {
		return ErrAccountNotFound
	}
	pubKeyData, err := hex.DecodeString(accData.PubKey)
	if err != nil {
		return err
	}
	pubKey, err := keypair.DeserializePublicKey(pubKeyData)
	if err != nil {
		return err
	}
	keyType := keypair.GetKeyType(pubKey)
	if CheckSigScheme(keyType, sigScheme) {
		return fmt.Errorf("sigScheme:%s does not match with KeyType:%s", sigScheme.Name(), accData.Alg)
	}
	accData.SigSch = sigScheme.Name()
	return nil
}

// ChangeAccountPassword -
func (w *Wallet) ChangeAccountPassword(address string, oldPassword, newPassword []byte) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	accData, ok := w.accAddressMap[address]
	if !ok {
		return ErrAccountNotFound
	}
	protectedKey, err := keypair.ReencryptPrivateKey(&accData.ProtectedKey, oldPassword, newPassword, w.Scrypt, w.Scrypt)
	if err != nil {
		return err
	}
	accData.SetKeyPair(protectedKey)
	return nil
}

// ImportAccounts -
func (w *Wallet) ImportAccounts(accountDatas []*AccountData, passwds [][]byte) error {
	if len(accountDatas) != len(passwds) {
		return fmt.Errorf("account size doesnot math password size")
	}
	for i := 0; i < len(accountDatas); i++ {
		accData := accountDatas[i]
		protectedkey, err := keypair.ReencryptPrivateKey(&accData.ProtectedKey, passwds[i], passwds[i], accData.GetScrypt(), w.Scrypt)
		if err != nil {
			return fmt.Errorf("ReencryptPrivateKey address:%s error:%s", accData.Address, err)
		}
		newAccData := &AccountData{
			PubKey:    accData.PubKey,
			SigSch:    accData.SigSch,
			Lock:      accData.Lock,
			IsDefault: false,
			Label:     accData.Label,
		}
		newAccData.SetKeyPair(protectedkey)
		_, err = w.GetAccountDataByLabel(accData.Label)
		if err != nil {
			//duplicate label, rename
			newAccData.Label = fmt.Sprintf("%s_1", accData.Label)
		}
		err = w.AddAccountData(newAccData)
		if err != nil {
			return fmt.Errorf("import account: %s , error:%s", accData.Address, err)
		}
	}
	return nil
}

// ExportAccounts -
func (w *Wallet) ExportAccounts(path string, accountDatas []*AccountData, passwds [][]byte, newScrypts ...*keypair.ScryptParam) (*Wallet, error) {
	var newScrypt keypair.ScryptParam
	if len(newScrypts) == 0 {
		newScrypt = *w.Scrypt
	} else {
		newScrypt = *newScrypts[0]
	}
	if len(accountDatas) != len(passwds) {
		return nil, fmt.Errorf("account size doesnot math password size")
	}
	newWallet := NewWallet(path)
	newWallet.Scrypt = &newScrypt
	for i := 0; i < len(accountDatas); i++ {
		accData := accountDatas[i]
		protectedkey, err := keypair.ReencryptPrivateKey(&accData.ProtectedKey, passwds[i], passwds[i], w.Scrypt, &newScrypt)
		if err != nil {
			return nil, fmt.Errorf("ReencryptPrivateKey address:%s error:%s", accData.Address, err)
		}
		newAccData := &AccountData{
			PubKey:    accData.PubKey,
			SigSch:    accData.SigSch,
			Lock:      accData.Lock,
			IsDefault: false,
			Label:     accData.Label,
		}
		newAccData.SetKeyPair(protectedkey)
		err = newWallet.AddAccountData(newAccData)
		if err != nil {
			return nil, fmt.Errorf("export account:%s error:%s", accData.Address, err)
		}
	}
	return newWallet, nil
}

// NewIdentity -
func (w *Wallet) NewIdentity(keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte) (*Identity, error) {
	identity, err := NewIdentity(w.Scrypt)
	if err != nil {
		return nil, err
	}
	//Key Index start from 1
	controllerID := "1"
	controllerData, err := NewControllerData(controllerID, keyType, curveCode, sigScheme, passwd, w.Scrypt)
	if err != nil {
		return nil, err
	}
	err = identity.AddControllerData(controllerData)
	if err != nil {
		return nil, err
	}
	err = w.AddIdentity(identity)
	if err != nil {
		return nil, err
	}
	return identity, nil
}

// NewDefaultSettingIdentity -
func (w *Wallet) NewDefaultSettingIdentity(passwd []byte) (*Identity, error) {
	return w.NewIdentity(keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, passwd)
}

// GetDefaultIdentity -
func (w *Wallet) GetDefaultIdentity() (*Identity, error) {
	w.lock.RLock()
	defer w.lock.RUnlock()
	if w.defIdentity == nil {
		return nil, fmt.Errorf("not set default identity")
	}
	return w.defIdentity, nil
}

// SetDefaultIdentity -
func (w *Wallet) SetDefaultIdentity(id string) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	identity, ok := w.identityMap[id]
	if !ok {
		return ErrIdentityNotFound
	}
	if w.defIdentity != nil {
		w.defIdentity.IsDefault = false
	}
	identity.IsDefault = true
	w.defIdentity = identity
	return nil
}

// AddIdentity -
func (w *Wallet) AddIdentity(identity *Identity) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	if w.defIdentity != nil && identity.IsDefault {
		return fmt.Errorf("already have default identity")
	}
	if w.defIdentity == nil {
		w.defIdentity = identity
		identity.IsDefault = true
	}
	w.identities = append(w.identities, identity)
	w.identityMap[identity.ID] = identity
	return nil
}

// DeleteIdentity -
func (w *Wallet) DeleteIdentity(id string) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	identity, ok := w.identityMap[id]
	if !ok {
		return ErrIdentityNotFound
	}
	if w.defIdentity.ID == id {
		return fmt.Errorf("cannot delete default identity")
	}
	delete(w.identityMap, id)
	if identity.Label != "" {
		delete(w.identityLabelMap, identity.Label)
	}
	size := len(w.identities)
	for index, ontID := range w.identities {
		if ontID.ID != id {
			continue
		}
		if size-1 == index {
			w.identities = w.identities[:index]
		} else {
			w.identities = append(w.identities[:index], w.identities[index+1:]...)
		}
		break
	}
	return nil
}

// GetIdentityByID -
func (w *Wallet) GetIdentityByID(id string) (*Identity, error) {
	w.lock.RLock()
	defer w.lock.RUnlock()
	identity, ok := w.identityMap[id]
	if !ok {
		return nil, ErrIdentityNotFound
	}
	return identity, nil
}

// GetIdentityByLabel -
func (w *Wallet) GetIdentityByLabel(label string) (*Identity, error) {
	w.lock.RLock()
	defer w.lock.RUnlock()
	identity, ok := w.identityLabelMap[label]
	if !ok {
		return nil, ErrIdentityNotFound
	}
	return identity, nil
}

// GetIdentityByIndex -
// Index start from 1
func (w *Wallet) GetIdentityByIndex(index int) (*Identity, error) {
	w.lock.RLock()
	defer w.lock.RUnlock()
	if index <= 0 || index > len(w.identities) {
		return nil, fmt.Errorf("index out of range")
	}
	return w.identities[index-1], nil
}

// SetIdentityLabel -
func (w *Wallet) SetIdentityLabel(id, newLabel string) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	identity, ok := w.identityMap[id]
	if !ok {
		return ErrIdentityNotFound
	}
	if identity.Label == newLabel {
		return nil
	}
	if newLabel == "" {
		delete(w.identityLabelMap, identity.Label)
		identity.Label = ""
		return nil
	}
	_, ok = w.identityLabelMap[newLabel]
	if ok {
		return fmt.Errorf("duplicate label")
	}
	identity.Label = newLabel
	w.identityLabelMap[newLabel] = identity
	return nil
}

// GetIdentityCount -
func (w *Wallet) GetIdentityCount() int {
	w.lock.RLock()
	defer w.lock.RUnlock()
	return len(w.identities)
}

// Save -
func (w *Wallet) Save() error {
	w.lock.RLock()
	walletData := &WalletData{
		Name:       w.Name,
		Version:    w.Version,
		Scrypt:     w.Scrypt,
		Identities: make([]*IdentityData, 0),
		Accounts:   make([]*AccountData, 0),
		Extra:      w.Extra,
	}
	for _, identity := range w.identities {
		walletData.Identities = append(walletData.Identities, identity.ToIdentityData())
	}
	for _, acc := range w.accounts {
		walletData.Accounts = append(walletData.Accounts, acc)
	}
	w.lock.RUnlock()
	return walletData.Save(w.path)
}

// WalletData -
type WalletData struct {
	Name       string               `json:"name"`
	Version    string               `json:"version"`
	Scrypt     *keypair.ScryptParam `json:"scrypt"`
	Identities []*IdentityData      `json:"identities,omitempty"`
	Accounts   []*AccountData       `json:"accounts,omitempty"`
	Extra      string               `json:"extra,omitempty"`
}

// NewWalletData -
func NewWalletData() *WalletData {
	return &WalletData{
		Name:       "MyWallet",
		Version:    "1.1",
		Scrypt:     keypair.GetScryptParameters(),
		Identities: nil,
		Extra:      "",
		Accounts:   make([]*AccountData, 0, 0),
	}
}

// Clone -
func (wd *WalletData) Clone() *WalletData {
	w := WalletData{}
	w.Name = wd.Name
	w.Version = wd.Version
	sp := *wd.Scrypt
	w.Scrypt = &sp
	w.Accounts = make([]*AccountData, len(wd.Accounts))
	for i, v := range wd.Accounts {
		ac := *v
		ac.SetKeyPair(v.GetKeyPair())
		w.Accounts[i] = &ac
	}
	w.Identities = wd.Identities
	w.Extra = wd.Extra
	return &w
}

// Save -
func (wd *WalletData) Save(path string) error {
	data, err := json.Marshal(wd)
	if err != nil {
		return err
	}
	if common.FileExisted(path) {
		filename := path + "~"
		err := ioutil.WriteFile(filename, data, 0644)
		if err != nil {
			return err
		}
		return os.Rename(filename, path)
	}
	return ioutil.WriteFile(path, data, 0644)
}

// Load -
func (wd *WalletData) Load(path string) error {
	msh, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(msh, wd)
}

// ScryptEqual -
func ScryptEqual(s1, s2 *keypair.ScryptParam) bool {
	return s1.DKLen == s2.DKLen && s1.N == s2.N && s1.P == s2.P && s1.R == s2.R
}
