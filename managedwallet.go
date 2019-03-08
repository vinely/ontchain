package ontchain

import (
	"errors"

	jsoniter "github.com/json-iterator/go"
	kvdb "github.com/vinely/kvdb"
	sdk "github.com/vinely/ontchain/ontsdk"
)

var (
	// FirstRevision - first or default revision
	FirstRevision = "0.1.0"
)

// WalletStorage - wallet storage information
type WalletStorage struct {
	FilePath string
	KVDB     kvdb.KVMethods `json:"-"`
}

// wallet storage status
const (
	NotStored = iota
	PartStored
	AllStored
)

// Status - wallet storage status
func (ws *WalletStorage) Status() int {
	if ws.FilePath == "" && ws.KVDB == nil {
		return NotStored
	}
	if ws.FilePath != "" && ws.KVDB != nil {
		return AllStored
	}
	return PartStored
}

// ManagedWallet - managed wallet
// Save password and walletdata in struct. Easier saving and loading data to database or storage
// 1, Load the data, then using "Update" function to refresh the wallet
// 2, get "walletData" from wallet information. After setting password and path then "Update" also can get managedwallet
// 3, "NewUpdatedManagedWallet" to get a full new managedwallet.
// 4, "GetWallet" to get wallet from managedwallet.
type ManagedWallet struct {
	Name     string // ID/Key of wallet
	Revision string // revision of wallet format or something information
	Info     string // extended information
	WalletStorage
	Password    []byte
	Data        sdk.WalletData
	Wallet      *sdk.Wallet   `json:"-"`
	DefAccout   *sdk.Account  `json:"-"`
	DefIdentity *sdk.Identity `json:"-"`
}

// NewManagedWallet - Create a new managedwallet
func NewManagedWallet(name string, rev string, password []byte) *ManagedWallet {
	w := sdk.NewWallet("")
	mw := &ManagedWallet{
		Name:     name,
		Revision: rev,
		Password: password,
		Wallet:   w,
	}
	return mw
}

// NewDefaultWallet - Creart new default revision and path "" Wallet
func NewDefaultWallet(name string, password []byte) *ManagedWallet {
	return NewManagedWallet(name, FirstRevision, password)
}

// NewUpdatedManagedWallet - Create a new managedwallet
func NewUpdatedManagedWallet(name string, password []byte) *ManagedWallet {

	mw := NewManagedWallet(name, FirstRevision, password)
	mw.DefAccout, _ = mw.Wallet.NewDefaultSettingAccount(password)
	mw.DefIdentity, _ = mw.Wallet.NewDefaultSettingIdentity(password)
	mw.UpdateWalletData()
	return mw
}

// UpdateWalletData - update walletdata from ManagedWallet.Wallet to ManagedWallet.Data
func (mw *ManagedWallet) UpdateWalletData() {
	mw.Data = mw.Wallet.GetWalletData()
}

// Update -
// after get walletdata from json
// update to *wallet and * account
func (mw *ManagedWallet) Update() error {
	w, err := sdk.LoadWalletFromData(mw.Data, mw.FilePath)
	if err != nil {
		return err
	}
	mw.Wallet = w
	mw.DefAccout, err = w.GetDefaultAccount(mw.Password)
	if err != nil {
		return err
	}
	mw.DefIdentity, err = w.GetDefaultIdentity()
	if err != nil {
		return err
	}
	return nil
}

// GetWallet - get managedwallet's wallet
func (mw *ManagedWallet) GetWallet() *sdk.Wallet {
	return mw.Wallet
}

// SetFilePath - Save wallet to wallet file(path)
func (mw *ManagedWallet) SetFilePath(path string, force bool) error {
	if mw.FilePath != "" && !force {
		return errors.New("Already have  filepath parameter")
	}
	mw.FilePath = path
	mw.Update()
	return mw.Wallet.Save()
}

// SetDB - store managewallet into the db
func (mw *ManagedWallet) SetDB(db kvdb.KVMethods) *sdk.Wallet {
	mw.KVDB = db
	ret := db.SetData(mw.Name, *mw)
	if ret.Result {
		return mw.Wallet
	}
	return nil
}

// GetManagedWalletFromDB - load managedwallet from database
func GetManagedWalletFromDB(db kvdb.KVMethods, key string) *ManagedWallet {
	ret := db.Get(key)
	if ret.Result {
		var json = jsoniter.ConfigCompatibleWithStandardLibrary
		var v ManagedWallet
		err := json.Unmarshal(ret.Data.([]byte), &v)
		if err != nil {
			return nil
		}
		v.KVDB = db
		v.Update()
		return &v
	}
	return nil
}

// GetManagedWalletFromFile - load managedwallet from wallet file
func GetManagedWalletFromFile(path string) *ManagedWallet {
	mw := &ManagedWallet{
		Name:     "file_" + path,
		Revision: FirstRevision,
	}
	mw.Data = sdk.WalletData{}
	err := mw.Data.Load(path)
	if err != nil {
		return nil
	}
	mw.FilePath = path
	mw.Update()
	return mw
}
