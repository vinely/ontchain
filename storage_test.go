package ontchain

import (
	"fmt"
	"testing"
)

type testsimplestorage struct {
	key   []byte
	value []byte
}

func TestPutSimpleStorage(t *testing.T) {
	tss := testsimplestorage{
		[]byte("ksxie"),
		[]byte("brd"),
	}
	w := testCreateWallet()
	acct, _ := w.Wallet.GetDefaultAccount(w.Password)
	_, err := PutSimpleStorage(acct, tss.key, tss.value)
	if err != nil {
		t.Error(err)
	}
}

func TestRemoveSimpleStorage(t *testing.T) {
	tss := testsimplestorage{
		key: []byte("ksxie"),
	}
	w := testCreateWallet()
	acct, _ := w.Wallet.GetDefaultAccount(w.Password)
	_, err := RemoveSimpleStorage(acct, tss.key)
	if err != nil {
		t.Error(err)
	}
}

func TestPostSimpleStorage(t *testing.T) {
	tss := testsimplestorage{
		[]byte("ksxie"),
		[]byte("bhnfg"),
	}
	w := testCreateWallet()
	acct, _ := w.Wallet.GetDefaultAccount(w.Password)
	_, err := PostSimpleStorage(acct, tss.key, tss.value)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("testsimplestorage %v\n", tss)
}

func TestGetSimpleStorage(t *testing.T) {
	tss := testsimplestorage{
		key: []byte("ksxie"),
	}
	rest := GetSimpleStorage(tss.key)
	if rest != nil {
		fmt.Println("ok")
		tss.value, _ = rest.Result.ToByteArray()
		fmt.Printf("Result :%s\n", tss.value)
		fmt.Printf("State :%v\n", rest.State)
	}
}
