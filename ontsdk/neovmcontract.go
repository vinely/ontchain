package ontsdk

import (
	"encoding/hex"
	"fmt"
	"time"

	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
	httpcom "github.com/ontio/ontology/http/base/common"
)

// NeoVMContract -
type NeoVMContract struct {
	ontSdk *OntologySdk
}

func newNeoVMContract(ontSdk *OntologySdk) *NeoVMContract {
	return &NeoVMContract{
		ontSdk: ontSdk,
	}
}

// NewDeployNeoVMCodeTransaction -
func (nc *NeoVMContract) NewDeployNeoVMCodeTransaction(gasPrice, gasLimit uint64, contract *sdkcom.SmartContract) *types.MutableTransaction {
	deployPayload := &payload.DeployCode{
		Code:        contract.Code,
		NeedStorage: contract.NeedStorage,
		Name:        contract.Name,
		Version:     contract.Version,
		Author:      contract.Author,
		Email:       contract.Email,
		Description: contract.Description,
	}
	tx := &types.MutableTransaction{
		Version:  sdkcom.VERSION_TRANSACTION,
		TxType:   types.Deploy,
		Nonce:    uint32(time.Now().Unix()),
		Payload:  deployPayload,
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		Sigs:     make([]types.Sig, 0, 0),
	}
	return tx
}

// DeployNeoVMSmartContract - Deploy smart contract to ontology
func (nc *NeoVMContract) DeployNeoVMSmartContract(
	gasPrice,
	gasLimit uint64,
	singer *Account,
	needStorage bool,
	code,
	name,
	version,
	author,
	email,
	desc string) (common.Uint256, error) {

	invokeCode, err := hex.DecodeString(code)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("code hex decode error:%s", err)
	}
	tx := nc.NewDeployNeoVMCodeTransaction(gasPrice, gasLimit, &sdkcom.SmartContract{
		Code:        invokeCode,
		NeedStorage: needStorage,
		Name:        name,
		Version:     version,
		Author:      author,
		Email:       email,
		Description: desc,
	})
	err = nc.ontSdk.SignToTransaction(tx, singer)
	if err != nil {
		return common.Uint256{}, err
	}
	txHash, err := nc.ontSdk.SendTransaction(tx)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SendRawTransaction error:%s", err)
	}
	return txHash, nil
}

// NewNeoVMInvokeTransaction -
func (nc *NeoVMContract) NewNeoVMInvokeTransaction(
	gasPrice,
	gasLimit uint64,
	contractAddress common.Address,
	params []interface{},
) (*types.MutableTransaction, error) {
	invokeCode, err := httpcom.BuildNeoVMInvokeCode(contractAddress, params)
	if err != nil {
		return nil, err
	}
	return nc.ontSdk.NewInvokeTransaction(gasPrice, gasLimit, invokeCode), nil
}

// InvokeNeoVMContract -
func (nc *NeoVMContract) InvokeNeoVMContract(
	gasPrice,
	gasLimit uint64,
	signer *Account,
	contractAddress common.Address,
	params []interface{}) (common.Uint256, error) {
	tx, err := nc.NewNeoVMInvokeTransaction(gasPrice, gasLimit, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("NewNeoVMInvokeTransaction error:%s", err)
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// PreExecInvokeNeoVMContract -
func (nc *NeoVMContract) PreExecInvokeNeoVMContract(
	contractAddress common.Address,
	params []interface{}) (*sdkcom.PreExecResult, error) {
	tx, err := nc.NewNeoVMInvokeTransaction(0, 0, contractAddress, params)
	if err != nil {
		return nil, err
	}
	return nc.ontSdk.PreExecTransaction(tx)
}
