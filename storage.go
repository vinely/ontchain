package ontchain

import (
	"log"

	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology/common"
	sdk "github.com/vinely/ontchain/ontsdk"
)

var (
	storagecontract = "015772ced12816c00ffe6812787a97fb612893dc"
)

// PutSimpleStorage - create simple storage
func PutSimpleStorage(acct *sdk.Account, key, value []byte) (common.Uint256, error) {
	sdk := GetSdk("")
	params := make([]interface{}, 0)
	params = append(params, []byte("Put"))

	p := []interface{}{
		key, value,
	}
	params = append(params, p)
	addr, _ := common.AddressFromHexString(storagecontract)
	return sdk.NeoVM.InvokeNeoVMContract(0, 20000, acct, addr, params)
}

// RemoveSimpleStorage - remove simple storage
func RemoveSimpleStorage(acct *sdk.Account, key []byte) (common.Uint256, error) {
	sdk := GetSdk("")
	params := make([]interface{}, 0)
	params = append(params, []byte("Remove"))

	p := []interface{}{
		key,
	}
	params = append(params, p)
	addr, _ := common.AddressFromHexString(storagecontract)
	return sdk.NeoVM.InvokeNeoVMContract(0, 20000, acct, addr, params)
}

// PostSimpleStorage - post simple storage
func PostSimpleStorage(acct *sdk.Account, key, value []byte) (common.Uint256, error) {
	sdk := GetSdk("")
	params := make([]interface{}, 0)
	params = append(params, []byte("Post"))

	p := []interface{}{
		key, value,
	}
	params = append(params, p)
	addr, _ := common.AddressFromHexString(storagecontract)
	return sdk.NeoVM.InvokeNeoVMContract(0, 20000, acct, addr, params)
}

// GetSimpleStorage - get simple storage
func GetSimpleStorage(key []byte) *sdkcom.PreExecResult {
	sdk := GetSdk("")
	params := make([]interface{}, 0)
	params = append(params, []byte("Get"))

	p := []interface{}{
		key,
	}
	params = append(params, p)
	addr, _ := common.AddressFromHexString(storagecontract)
	rest, err := sdk.NeoVM.PreExecInvokeNeoVMContract(addr, params)
	if err != nil {
		log.Println(err)
		return nil
	}
	return rest
}
