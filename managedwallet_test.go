package ontchain

import (
	"fmt"
	"testing"

	kvdb "github.com/vinely/kvdb"
)

var (
	walletDB *kvdb.BoltDB
	// defaultWallet = NewUpdatedManagedWallet("bidderwallet", "./bidderwallet.dat", []byte("ZANgzFY54o25xtYp"))
)

func walletDBInit() {
	// d, _ := kvdb.NewKVDataBase("bolt://wallet.db/wallet?count=30")
	walletDB = GetWalletBoltDB("wallet.db", "wallet", 30)
}

func testCreateWallet() *ManagedWallet {
	return NewUpdatedManagedWallet("bidderwallet", []byte("ZANgzFY54o25xtYp"))
}

// GetWalletBoltDB - setup new wallet bolt db
// dbfile
func GetWalletBoltDB(dbfile string, bucket string, count uint) *kvdb.BoltDB {
	d, _ := kvdb.NewKVDataBase(fmt.Sprintf("bolt://%s/%s?count=%d", dbfile, bucket, count))
	return d.(*kvdb.BoltDB)
}

func TestNewUpdatedManagedWallet(t *testing.T) {
	walletDBInit()
	w := NewUpdatedManagedWallet("bidderwallet", []byte("ZANgzFY54o25xtYp"))
	w.SetFilePath("bidderwallet", true)
	w.SetDB(walletDB)

	fmt.Printf("%v\n", w)
}

func TestGetManagedWalletFromDB(t *testing.T) {
	walletDBInit()
	mw := GetManagedWalletFromDB(walletDB, "bidderwallet")
	fmt.Printf("%v\n", mw)
}

func TestGetManagedWalletFromFile(t *testing.T) {
	walletDBInit()
	mw := GetManagedWalletFromFile("bidderwallet")
	fmt.Printf("%v\n", mw)
}
