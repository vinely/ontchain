package ontchain

import (
	"encoding/hex"
	"fmt"

	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
	sdk "github.com/vinely/ontchain/ontsdk"
)

// GetTxInfo - get transaction infomation
func GetTxInfo(hash string) (*types.Transaction, error) {
	sdk := GetSdk("")
	return sdk.GetTransaction(hash)
}

// GetStorage - get smartcontract storage
func GetStorage(addr string, key []byte) ([]byte, error) {
	sdk := GetSdk("")
	return sdk.GetStorage(addr, key)
}

// GetSmartContractEvent - get smart contract event
func GetSmartContractEvent(txHash string) (*sdkcom.SmartContactEvent, error) {
	sdk := GetSdk("")
	return sdk.GetSmartContractEvent(txHash)
}

// SmartContract - smart contract
type SmartContract sdkcom.SmartContract

// DeployContract - deploy contract
func DeployContract(acct *sdk.Account, sc *sdkcom.SmartContract) (common.Uint256, error) {
	sdk := GetSdk("")
	tx := sdk.NeoVM.NewDeployNeoVMCodeTransaction(0, 20200000, sc)
	err := sdk.SignToTransaction(tx, acct)
	if err != nil {
		return common.Uint256{}, err
	}
	txHash, err := sdk.SendTransaction(tx)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SendRawTransaction error:%s", err)
	}
	return txHash, nil
}

// DeployContractCode - deploy contract code
func DeployContractCode(acct *sdk.Account, name, code string) (common.Uint256, error) {
	invokeCode, err := hex.DecodeString(code)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("code hex decode error:%s", err)
	}
	sc := &sdkcom.SmartContract{
		Code:        invokeCode,
		NeedStorage: true,
		Name:        name,
		Version:     "v1.0",
		Author:      "author",
		Email:       "email",
		Description: "desp",
	}
	return DeployContract(acct, sc)
}
