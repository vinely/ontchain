package ontsdk

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/serialization"
	"github.com/ontio/ontology/core/types"
	cutils "github.com/ontio/ontology/core/utils"
	"github.com/ontio/ontology/smartcontract/service/native/global_params"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
)

var (
	// OntContractAddress -
	OntContractAddress, _           = utils.AddressFromHexString("0100000000000000000000000000000000000000")
	// OngContractAddress -
	OngContractAddress, _           = utils.AddressFromHexString("0200000000000000000000000000000000000000")
	// OntIDContractAddress -
	OntIDContractAddress, _        = utils.AddressFromHexString("0300000000000000000000000000000000000000")
	// GlobalParamsContractAddress -
	GlobalParamsContractAddress, _ = utils.AddressFromHexString("0400000000000000000000000000000000000000")
	// AuthContractAddress -
	AuthContractAddress, _          = utils.AddressFromHexString("0600000000000000000000000000000000000000")
	// GovernanceContractAddress -
	GovernanceContractAddress, _    = utils.AddressFromHexString("0700000000000000000000000000000000000000")
)

var (
	// OntContractVersion -
	OntContractVersion           = byte(0)
	// OngContractVersion -
	OngContractVersion           = byte(0)
	// OntIDContractVersion -
	OntIDContractVersion        = byte(0)
	// GlobalParamsContractVersion -
	GlobalParamsContractVersion = byte(0)
	// AuthContractVersion -
	AuthContractVersion          = byte(0)
	// GovernanceContractVersion -
	GovernanceContractVersion    = byte(0)
)

// NativeContract -
type NativeContract struct {
	ontSdk       *OntologySdk
	Ont          *Ont
	Ong          *Ong
	OntID        *OntID
	GlobalParams *GlobalParam
	Auth         *Auth
}

func newNativeContract(ontSdk *OntologySdk) *NativeContract {
	native := &NativeContract{ontSdk: ontSdk}
	native.Ont = &Ont{native: native, ontSdk: ontSdk}
	native.Ong = &Ong{native: native, ontSdk: ontSdk}
	native.OntID = &OntID{native: native, ontSdk: ontSdk}
	native.GlobalParams = &GlobalParam{native: native, ontSdk: ontSdk}
	native.Auth = &Auth{native: native, ontSdk: ontSdk}
	return native
}

// NewNativeInvokeTransaction -
func (nc *NativeContract) NewNativeInvokeTransaction(
	gasPrice,
	gasLimit uint64,
	version byte,
	contractAddress common.Address,
	method string,
	params []interface{},
) (*types.MutableTransaction, error) {
	if params == nil {
		params = make([]interface{}, 0, 1)
	}
	//Params cannot empty, if params is empty, fulfil with empty string
	if len(params) == 0 {
		params = append(params, "")
	}
	invokeCode, err := cutils.BuildNativeInvokeCode(contractAddress, version, method, params)
	if err != nil {
		return nil, fmt.Errorf("BuildNativeInvokeCode error:%s", err)
	}
	return nc.ontSdk.NewInvokeTransaction(gasPrice, gasLimit, invokeCode), nil
}

// InvokeNativeContract -
func (nc *NativeContract) InvokeNativeContract(
	gasPrice,
	gasLimit uint64,
	singer *Account,
	version byte,
	contractAddress common.Address,
	method string,
	params []interface{},
) (common.Uint256, error) {
	tx, err := nc.NewNativeInvokeTransaction(gasPrice, gasLimit, version, contractAddress, method, params)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, singer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// PreExecInvokeNativeContract -
func (nc *NativeContract) PreExecInvokeNativeContract(
	contractAddress common.Address,
	version byte,
	method string,
	params []interface{},
) (*sdkcom.PreExecResult, error) {
	tx, err := nc.NewNativeInvokeTransaction(0, 0, version, contractAddress, method, params)
	if err != nil {
		return nil, err
	}
	return nc.ontSdk.PreExecTransaction(tx)
}

// Ont -
type Ont struct {
	ontSdk *OntologySdk
	native *NativeContract
}

// NewTransferTransaction -
func (o *Ont) NewTransferTransaction(gasPrice, gasLimit uint64, from, to common.Address, amount uint64) (*types.MutableTransaction, error) {
	state := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return o.NewMultiTransferTransaction(gasPrice, gasLimit, []*ont.State{state})
}

// Transfer -
func (o *Ont) Transfer(gasPrice, gasLimit uint64, from *Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := o.NewTransferTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = o.ontSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return o.ontSdk.SendTransaction(tx)
}

// NewMultiTransferTransaction -
func (o *Ont) NewMultiTransferTransaction(gasPrice, gasLimit uint64, states []*ont.State) (*types.MutableTransaction, error) {
	return o.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OntContractVersion,
		OntContractAddress,
		ont.TRANSFER_NAME,
		[]interface{}{states})
}

// MultiTransfer -
func (o *Ont) MultiTransfer(gasPrice, gasLimit uint64, states []*ont.State, signer *Account) (common.Uint256, error) {
	tx, err := o.NewMultiTransferTransaction(gasPrice, gasLimit, states)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = o.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return o.ontSdk.SendTransaction(tx)
}

// NewTransferFromTransaction -
func (o *Ont) NewTransferFromTransaction(gasPrice, gasLimit uint64, sender, from, to common.Address, amount uint64) (*types.MutableTransaction, error) {
	state := &ont.TransferFrom{
		Sender: sender,
		From:   from,
		To:     to,
		Value:  amount,
	}
	return o.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OntContractVersion,
		OntContractAddress,
		ont.TRANSFERFROM_NAME,
		[]interface{}{state},
	)
}

// TransferFrom -
func (o *Ont) TransferFrom(gasPrice, gasLimit uint64, sender *Account, from, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := o.NewTransferFromTransaction(gasPrice, gasLimit, sender.Address, from, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = o.ontSdk.SignToTransaction(tx, sender)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return o.ontSdk.SendTransaction(tx)
}

// NewApproveTransaction -
func (o *Ont) NewApproveTransaction(gasPrice, gasLimit uint64, from, to common.Address, amount uint64) (*types.MutableTransaction, error) {
	state := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return o.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OntContractVersion,
		OntContractAddress,
		ont.APPROVE_NAME,
		[]interface{}{state},
	)
}

// Approve -
func (o *Ont) Approve(gasPrice, gasLimit uint64, from *Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := o.NewApproveTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = o.ontSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return o.ontSdk.SendTransaction(tx)
}

// Allowance -
func (o *Ont) Allowance(from, to common.Address) (uint64, error) {
	type allowanceStruct struct {
		From common.Address
		To   common.Address
	}
	preResult, err := o.native.PreExecInvokeNativeContract(
		OntContractAddress,
		OntContractVersion,
		ont.ALLOWANCE_NAME,
		[]interface{}{&allowanceStruct{From: from, To: to}},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

// Symbol -
func (o *Ont) Symbol() (string, error) {
	preResult, err := o.native.PreExecInvokeNativeContract(
		OntContractAddress,
		OntContractVersion,
		ont.SYMBOL_NAME,
		[]interface{}{},
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

// BalanceOf -
func (o *Ont) BalanceOf(address common.Address) (uint64, error) {
	preResult, err := o.native.PreExecInvokeNativeContract(
		OntContractAddress,
		OntContractVersion,
		ont.BALANCEOF_NAME,
		[]interface{}{address[:]},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

// Name -
func (o *Ont) Name() (string, error) {
	preResult, err := o.native.PreExecInvokeNativeContract(
		OntContractAddress,
		OntContractVersion,
		ont.NAME_NAME,
		[]interface{}{},
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

// Decimals -
func (o *Ont) Decimals() (byte, error) {
	preResult, err := o.native.PreExecInvokeNativeContract(
		OntContractAddress,
		OntContractVersion,
		ont.DECIMALS_NAME,
		[]interface{}{},
	)
	if err != nil {
		return 0, err
	}
	decimals, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return byte(decimals.Uint64()), nil
}

// TotalSupply -
func (o *Ont) TotalSupply() (uint64, error) {
	preResult, err := o.native.PreExecInvokeNativeContract(
		OntContractAddress,
		OntContractVersion,
		ont.TOTAL_SUPPLY_NAME,
		[]interface{}{},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

// Ong -
type Ong struct {
	ontSdk *OntologySdk
	native *NativeContract
}

// NewTransferTransaction -
func (o *Ong) NewTransferTransaction(gasPrice, gasLimit uint64, from, to common.Address, amount uint64) (*types.MutableTransaction, error) {
	state := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return o.NewMultiTransferTransaction(gasPrice, gasLimit, []*ont.State{state})
}

// Transfer -
func (o *Ong) Transfer(gasPrice, gasLimit uint64, from *Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := o.NewTransferTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = o.ontSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return o.ontSdk.SendTransaction(tx)
}

// NewMultiTransferTransaction -
func (o *Ong) NewMultiTransferTransaction(gasPrice, gasLimit uint64, states []*ont.State) (*types.MutableTransaction, error) {
	return o.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OngContractVersion,
		OngContractAddress,
		ont.TRANSFER_NAME,
		[]interface{}{states})
}

// MultiTransfer -
func (o *Ong) MultiTransfer(gasPrice, gasLimit uint64, states []*ont.State, signer *Account) (common.Uint256, error) {
	tx, err := o.NewMultiTransferTransaction(gasPrice, gasLimit, states)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = o.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return o.ontSdk.SendTransaction(tx)
}

// NewTransferFromTransaction -
func (o *Ong) NewTransferFromTransaction(gasPrice, gasLimit uint64, sender, from, to common.Address, amount uint64) (*types.MutableTransaction, error) {
	state := &ont.TransferFrom{
		Sender: sender,
		From:   from,
		To:     to,
		Value:  amount,
	}
	return o.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OngContractVersion,
		OngContractAddress,
		ont.TRANSFERFROM_NAME,
		[]interface{}{state},
	)
}

// TransferFrom -
func (o *Ong) TransferFrom(gasPrice, gasLimit uint64, sender *Account, from, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := o.NewTransferFromTransaction(gasPrice, gasLimit, sender.Address, from, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = o.ontSdk.SignToTransaction(tx, sender)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return o.ontSdk.SendTransaction(tx)
}

// NewWithdrawONGTransaction -
func (o *Ong) NewWithdrawONGTransaction(gasPrice, gasLimit uint64, address common.Address, amount uint64) (*types.MutableTransaction, error) {
	return o.NewTransferFromTransaction(gasPrice, gasLimit, address, OntContractAddress, address, amount)
}

// WithdrawONG -
func (o *Ong) WithdrawONG(gasPrice, gasLimit uint64, address *Account, amount uint64) (common.Uint256, error) {
	tx, err := o.NewWithdrawONGTransaction(gasPrice, gasLimit, address.Address, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = o.ontSdk.SignToTransaction(tx, address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return o.ontSdk.SendTransaction(tx)
}

// NewApproveTransaction -
func (o *Ong) NewApproveTransaction(gasPrice, gasLimit uint64, from, to common.Address, amount uint64) (*types.MutableTransaction, error) {
	state := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return o.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OngContractVersion,
		OngContractAddress,
		ont.APPROVE_NAME,
		[]interface{}{state},
	)
}

// Approve -
func (o *Ong) Approve(gasPrice, gasLimit uint64, from *Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := o.NewApproveTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = o.ontSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return o.ontSdk.SendTransaction(tx)
}

// Allowance -
func (o *Ong) Allowance(from, to common.Address) (uint64, error) {
	type allowanceStruct struct {
		From common.Address
		To   common.Address
	}
	preResult, err := o.native.PreExecInvokeNativeContract(
		OngContractAddress,
		OngContractVersion,
		ont.ALLOWANCE_NAME,
		[]interface{}{&allowanceStruct{From: from, To: to}},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

// UnboundONG -
func (o *Ong) UnboundONG(address common.Address) (uint64, error) {
	return o.Allowance(OntContractAddress, address)
}

// Symbol -
func (o *Ong) Symbol() (string, error) {
	preResult, err := o.native.PreExecInvokeNativeContract(
		OngContractAddress,
		OngContractVersion,
		ont.SYMBOL_NAME,
		[]interface{}{},
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

// BalanceOf -
func (o *Ong) BalanceOf(address common.Address) (uint64, error) {
	preResult, err := o.native.PreExecInvokeNativeContract(
		OngContractAddress,
		OngContractVersion,
		ont.BALANCEOF_NAME,
		[]interface{}{address[:]},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

// Name - 
func (o *Ong) Name() (string, error) {
	preResult, err := o.native.PreExecInvokeNativeContract(
		OngContractAddress,
		OngContractVersion,
		ont.NAME_NAME,
		[]interface{}{},
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

// Decimals -
func (o *Ong) Decimals() (byte, error) {
	preResult, err := o.native.PreExecInvokeNativeContract(
		OngContractAddress,
		OngContractVersion,
		ont.DECIMALS_NAME,
		[]interface{}{},
	)
	if err != nil {
		return 0, err
	}
	decimals, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return byte(decimals.Uint64()), nil
}

// TotalSupply -
func (o *Ong) TotalSupply() (uint64, error) {
	preResult, err := o.native.PreExecInvokeNativeContract(
		OngContractAddress,
		OngContractVersion,
		ont.TOTAL_SUPPLY_NAME,
		[]interface{}{},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

// OntID -
type OntID struct {
	ontSdk *OntologySdk
	native *NativeContract
}

// NewRegIDWithPublicKeyTransaction -
func (nc *OntID) NewRegIDWithPublicKeyTransaction(gasPrice, gasLimit uint64, OntID string, pubKey keypair.PublicKey) (*types.MutableTransaction, error) {
	type regIDWithPublicKey struct {
		OntID  string
		PubKey []byte
	}
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OntIDContractVersion,
		OntIDContractAddress,
		"regIDWithPublicKey",
		[]interface{}{
			&regIDWithPublicKey{
				OntID:  OntID,
				PubKey: keypair.SerializePublicKey(pubKey),
			},
		},
	)
}

// RegIDWithPublicKey -
func (nc *OntID) RegIDWithPublicKey(gasPrice, gasLimit uint64, signer *Account, OntID string, controller *Controller) (common.Uint256, error) {
	tx, err := nc.NewRegIDWithPublicKeyTransaction(gasPrice, gasLimit, OntID, controller.PublicKey)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewRegIDWithAttributesTransaction -
func (nc *OntID) NewRegIDWithAttributesTransaction(gasPrice, gasLimit uint64, OntID string, pubKey keypair.PublicKey, attributes []*DDOAttribute) (*types.MutableTransaction, error) {
	type regIDWithAttribute struct {
		OntID      string
		PubKey     []byte
		Attributes []*DDOAttribute
	}
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OntIDContractVersion,
		OntIDContractAddress,
		"regIDWithAttributes",
		[]interface{}{
			&regIDWithAttribute{
				OntID:      OntID,
				PubKey:     keypair.SerializePublicKey(pubKey),
				Attributes: attributes,
			},
		},
	)
}

// RegIDWithAttributes -
func (nc *OntID) RegIDWithAttributes(gasPrice, gasLimit uint64, signer *Account, OntID string, controller *Controller, attributes []*DDOAttribute) (common.Uint256, error) {
	tx, err := nc.NewRegIDWithAttributesTransaction(gasPrice, gasLimit, OntID, controller.PublicKey, attributes)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// GetDDO -
func (nc *OntID) GetDDO(OntID string) (*DDO, error) {
	result, err := nc.native.PreExecInvokeNativeContract(
		OntIDContractAddress,
		OntIDContractVersion,
		"getDDO",
		[]interface{}{OntID},
	)
	if err != nil {
		return nil, err
	}
	data, err := result.Result.ToByteArray()
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(data)
	keyData, err := serialization.ReadVarBytes(buf)
	if err != nil {
		return nil, fmt.Errorf("key ReadVarBytes error:%s", err)
	}
	owners, err := nc.getPublicKeys(OntID, keyData)
	if err != nil {
		return nil, fmt.Errorf("getPublicKeys error:%s", err)
	}
	attrData, err := serialization.ReadVarBytes(buf)
	attrs, err := nc.getAttributes(OntID, attrData)
	if err != nil {
		return nil, fmt.Errorf("getAttributes error:%s", err)
	}
	recoveryData, err := serialization.ReadVarBytes(buf)
	if err != nil {
		return nil, fmt.Errorf("recovery ReadVarBytes error:%s", err)
	}
	var addr string
	if len(recoveryData) != 0 {
		address, err := common.AddressParseFromBytes(recoveryData)
		if err != nil {
			return nil, fmt.Errorf("AddressParseFromBytes error:%s", err)
		}
		addr = address.ToBase58()
	}

	ddo := &DDO{
		OntID:      OntID,
		Owners:     owners,
		Attributes: attrs,
		Recovery:   addr,
	}
	return ddo, nil
}

// NewAddKeyTransaction -
func (nc *OntID) NewAddKeyTransaction(gasPrice, gasLimit uint64, OntID string, newPubKey, pubKey keypair.PublicKey) (*types.MutableTransaction, error) {
	type addKey struct {
		OntID     string
		NewPubKey []byte
		PubKey    []byte
	}
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OntIDContractVersion,
		OntIDContractAddress,
		"addKey",
		[]interface{}{
			&addKey{
				OntID:     OntID,
				NewPubKey: keypair.SerializePublicKey(newPubKey),
				PubKey:    keypair.SerializePublicKey(pubKey),
			},
		})
}

// AddKey -
func (nc *OntID) AddKey(gasPrice, gasLimit uint64, OntID string, signer *Account, newPubKey keypair.PublicKey, controller *Controller) (common.Uint256, error) {
	tx, err := nc.NewAddKeyTransaction(gasPrice, gasLimit, OntID, newPubKey, controller.PublicKey)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewRevokeKeyTransaction -
func (nc *OntID) NewRevokeKeyTransaction(gasPrice, gasLimit uint64, OntID string, removedPubKey, pubKey keypair.PublicKey) (*types.MutableTransaction, error) {
	type removeKey struct {
		OntID      string
		RemovedKey []byte
		PubKey     []byte
	}
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OntIDContractVersion,
		OntIDContractAddress,
		"removeKey",
		[]interface{}{
			&removeKey{
				OntID:      OntID,
				RemovedKey: keypair.SerializePublicKey(removedPubKey),
				PubKey:     keypair.SerializePublicKey(pubKey),
			},
		},
	)
}

// RevokeKey -
func (nc *OntID) RevokeKey(gasPrice, gasLimit uint64, OntID string, signer *Account, removedPubKey keypair.PublicKey, controller *Controller) (common.Uint256, error) {
	tx, err := nc.NewRevokeKeyTransaction(gasPrice, gasLimit, OntID, removedPubKey, controller.PublicKey)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewSetRecoveryTransaction -
func (nc *OntID) NewSetRecoveryTransaction(gasPrice, gasLimit uint64, OntID string, recovery common.Address, pubKey keypair.PublicKey) (*types.MutableTransaction, error) {
	type addRecovery struct {
		OntID    string
		Recovery common.Address
		Pubkey   []byte
	}
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OntIDContractVersion,
		OntIDContractAddress,
		"addRecovery",
		[]interface{}{
			&addRecovery{
				OntID:    OntID,
				Recovery: recovery,
				Pubkey:   keypair.SerializePublicKey(pubKey),
			},
		})
}

// SetRecovery -
func (nc *OntID) SetRecovery(gasPrice, gasLimit uint64, signer *Account, OntID string, recovery common.Address, controller *Controller) (common.Uint256, error) {
	tx, err := nc.NewSetRecoveryTransaction(gasPrice, gasLimit, OntID, recovery, controller.PublicKey)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewChangeRecoveryTransaction -
func (nc *OntID) NewChangeRecoveryTransaction(gasPrice, gasLimit uint64, OntID string, newRecovery, oldRecovery common.Address) (*types.MutableTransaction, error) {
	type changeRecovery struct {
		OntID       string
		NewRecovery common.Address
		OldRecovery common.Address
	}
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OntIDContractVersion,
		OntIDContractAddress,
		"changeRecovery",
		[]interface{}{
			&changeRecovery{
				OntID:       OntID,
				NewRecovery: newRecovery,
				OldRecovery: oldRecovery,
			},
		})
}

// ChangeRecovery -
func (nc *OntID) ChangeRecovery(gasPrice, gasLimit uint64, signer *Account, OntID string, newRecovery, oldRecovery common.Address, controller *Controller) (common.Uint256, error) {
	tx, err := nc.NewChangeRecoveryTransaction(gasPrice, gasLimit, OntID, newRecovery, oldRecovery)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewAddAttributesTransaction -
func (nc *OntID) NewAddAttributesTransaction(gasPrice, gasLimit uint64, OntID string, attributes []*DDOAttribute, pubKey keypair.PublicKey) (*types.MutableTransaction, error) {
	type addAttributes struct {
		OntID      string
		Attributes []*DDOAttribute
		PubKey     []byte
	}
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OntIDContractVersion,
		OntIDContractAddress,
		"addAttributes",
		[]interface{}{
			&addAttributes{
				OntID:      OntID,
				Attributes: attributes,
				PubKey:     keypair.SerializePublicKey(pubKey),
			},
		})
}

// AddAttributes -
func (nc *OntID) AddAttributes(gasPrice, gasLimit uint64, signer *Account, OntID string, attributes []*DDOAttribute, controller *Controller) (common.Uint256, error) {
	tx, err := nc.NewAddAttributesTransaction(gasPrice, gasLimit, OntID, attributes, controller.PublicKey)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return nc.ontSdk.SendTransaction(tx)
}

// NewRemoveAttributeTransaction -
func (nc *OntID) NewRemoveAttributeTransaction(gasPrice, gasLimit uint64, OntID string, key []byte, pubKey keypair.PublicKey) (*types.MutableTransaction, error) {
	type removeAttribute struct {
		OntID  string
		Key    []byte
		PubKey []byte
	}
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		OntIDContractVersion,
		OntIDContractAddress,
		"removeAttribute",
		[]interface{}{
			&removeAttribute{
				OntID:  OntID,
				Key:    key,
				PubKey: keypair.SerializePublicKey(pubKey),
			},
		})
}

// RemoveAttribute -
func (nc *OntID) RemoveAttribute(gasPrice, gasLimit uint64, signer *Account, OntID string, removeKey []byte, controller *Controller) (common.Uint256, error) {
	tx, err := nc.NewRemoveAttributeTransaction(gasPrice, gasLimit, OntID, removeKey, controller.PublicKey)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return nc.ontSdk.SendTransaction(tx)
}

// GetAttributes -
func (nc *OntID) GetAttributes(OntID string) ([]*DDOAttribute, error) {
	preResult, err := nc.native.PreExecInvokeNativeContract(
		OntIDContractAddress,
		OntIDContractVersion,
		"getAttributes",
		[]interface{}{OntID})
	if err != nil {
		return nil, err
	}
	data, err := preResult.Result.ToByteArray()
	if err != nil {
		return nil, fmt.Errorf("ToByteArray error:%s", err)
	}
	return nc.getAttributes(OntID, data)
}

func (nc *OntID) getAttributes(OntID string, data []byte) ([]*DDOAttribute, error) {
	buf := bytes.NewBuffer(data)
	attributes := make([]*DDOAttribute, 0)
	for {
		if buf.Len() == 0 {
			break
		}
		key, err := serialization.ReadVarBytes(buf)
		if err != nil {
			return nil, fmt.Errorf("key ReadVarBytes error:%s", err)
		}
		valueType, err := serialization.ReadVarBytes(buf)
		if err != nil {
			return nil, fmt.Errorf("value type ReadVarBytes error:%s", err)
		}
		value, err := serialization.ReadVarBytes(buf)
		if err != nil {
			return nil, fmt.Errorf("value ReadVarBytes error:%s", err)
		}
		attributes = append(attributes, &DDOAttribute{
			Key:       key,
			Value:     value,
			ValueType: valueType,
		})
	}
	//reverse
	for i, j := 0, len(attributes)-1; i < j; i, j = i+1, j-1 {
		attributes[i], attributes[j] = attributes[j], attributes[i]
	}
	return attributes, nil
}

// VerifySignature -
func (nc *OntID) VerifySignature(OntID string, keyIndex int, controller *Controller) (bool, error) {
	tx, err := nc.native.NewNativeInvokeTransaction(
		0, 0,
		OntIDContractVersion,
		OntIDContractAddress,
		"verifySignature",
		[]interface{}{OntID, keyIndex})
	if err != nil {
		return false, err
	}
	err = nc.ontSdk.SignToTransaction(tx, controller)
	if err != nil {
		return false, err
	}
	preResult, err := nc.ontSdk.PreExecTransaction(tx)
	if err != nil {
		return false, err
	}
	return preResult.Result.ToBool()
}

// GetPublicKeys -
func (nc *OntID) GetPublicKeys(OntID string) ([]*DDOOwner, error) {
	preResult, err := nc.native.PreExecInvokeNativeContract(
		OntIDContractAddress,
		OntIDContractVersion,
		"getPublicKeys",
		[]interface{}{
			OntID,
		})
	if err != nil {
		return nil, err
	}
	data, err := preResult.Result.ToByteArray()
	if err != nil {
		return nil, err
	}
	return nc.getPublicKeys(OntID, data)
}

// getPublicKeys -
func (nc *OntID) getPublicKeys(OntID string, data []byte) ([]*DDOOwner, error) {
	buf := bytes.NewBuffer(data)
	owners := make([]*DDOOwner, 0)
	for {
		if buf.Len() == 0 {
			break
		}
		index, err := serialization.ReadUint32(buf)
		if err != nil {
			return nil, fmt.Errorf("index ReadUint32 error:%s", err)
		}
		pubKeyID := fmt.Sprintf("%s#keys-%d", OntID, index)
		pkData, err := serialization.ReadVarBytes(buf)
		if err != nil {
			return nil, fmt.Errorf("PubKey Idenx:%d ReadVarBytes error:%s", index, err)
		}
		pubKey, err := keypair.DeserializePublicKey(pkData)
		if err != nil {
			return nil, fmt.Errorf("DeserializePublicKey Index:%d error:%s", index, err)
		}
		keyType := keypair.GetKeyType(pubKey)
		owner := &DDOOwner{
			pubKeyIndex: index,
			PubKeyID:    pubKeyID,
			Type:        GetKeyTypeString(keyType),
			Curve:       GetCurveName(pkData),
			Value:       hex.EncodeToString(pkData),
		}
		owners = append(owners, owner)
	}
	return owners, nil
}

// GetKeyState -
func (nc *OntID) GetKeyState(OntID string, keyIndex int) (string, error) {
	type keyState struct {
		OntID    string
		KeyIndex int
	}
	preResult, err := nc.native.PreExecInvokeNativeContract(
		OntIDContractAddress,
		OntIDContractVersion,
		"getKeyState",
		[]interface{}{
			&keyState{
				OntID:    OntID,
				KeyIndex: keyIndex,
			},
		})
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

// GlobalParam -
type GlobalParam struct {
	ontSdk *OntologySdk
	native *NativeContract
}

// GetGlobalParams -
func (nc *GlobalParam) GetGlobalParams(params []string) (map[string]string, error) {
	preResult, err := nc.native.PreExecInvokeNativeContract(
		GlobalParamsContractAddress,
		GlobalParamsContractVersion,
		global_params.GET_GLOBAL_PARAM_NAME,
		[]interface{}{params})
	if err != nil {
		return nil, err
	}
	results, err := preResult.Result.ToByteArray()
	if err != nil {
		return nil, err
	}
	queryParams := new(global_params.Params)
	err = queryParams.Deserialize(bytes.NewBuffer(results))
	if err != nil {
		return nil, err
	}
	globalParams := make(map[string]string, len(params))
	for _, param := range params {
		index, values := queryParams.GetParam(param)
		if index < 0 {
			continue
		}
		globalParams[param] = values.Value
	}
	return globalParams, nil
}

// NewSetGlobalParamsTransaction -
func (nc *GlobalParam) NewSetGlobalParamsTransaction(gasPrice, gasLimit uint64, params map[string]string) (*types.MutableTransaction, error) {
	var globalParams global_params.Params
	for k, v := range params {
		globalParams.SetParam(global_params.Param{Key: k, Value: v})
	}
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		GlobalParamsContractVersion,
		GlobalParamsContractAddress,
		global_params.SET_GLOBAL_PARAM_NAME,
		[]interface{}{globalParams})
}

// SetGlobalParams -
func (nc *GlobalParam) SetGlobalParams(gasPrice, gasLimit uint64, signer *Account, params map[string]string) (common.Uint256, error) {
	tx, err := nc.NewSetGlobalParamsTransaction(gasPrice, gasLimit, params)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewTransferAdminTransaction -
func (nc *GlobalParam) NewTransferAdminTransaction(gasPrice, gasLimit uint64, newAdmin common.Address) (*types.MutableTransaction, error) {
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		GlobalParamsContractVersion,
		GlobalParamsContractAddress,
		global_params.TRANSFER_ADMIN_NAME,
		[]interface{}{newAdmin})
}

// TransferAdmin -
func (nc *GlobalParam) TransferAdmin(gasPrice, gasLimit uint64, signer *Account, newAdmin common.Address) (common.Uint256, error) {
	tx, err := nc.NewTransferAdminTransaction(gasPrice, gasLimit, newAdmin)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewAcceptAdminTransaction -
func (nc *GlobalParam) NewAcceptAdminTransaction(gasPrice, gasLimit uint64, admin common.Address) (*types.MutableTransaction, error) {
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		GlobalParamsContractVersion,
		GlobalParamsContractAddress,
		global_params.ACCEPT_ADMIN_NAME,
		[]interface{}{admin})
}

// AcceptAdmin -
func (nc *GlobalParam) AcceptAdmin(gasPrice, gasLimit uint64, signer *Account) (common.Uint256, error) {
	tx, err := nc.NewAcceptAdminTransaction(gasPrice, gasLimit, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewSetOperatorTransaction -
func (nc *GlobalParam) NewSetOperatorTransaction(gasPrice, gasLimit uint64, operator common.Address) (*types.MutableTransaction, error) {
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		GlobalParamsContractVersion,
		GlobalParamsContractAddress,
		global_params.SET_OPERATOR,
		[]interface{}{operator},
	)
}

// SetOperator -
func (nc *GlobalParam) SetOperator(gasPrice, gasLimit uint64, signer *Account, operator common.Address) (common.Uint256, error) {
	tx, err := nc.NewSetOperatorTransaction(gasPrice, gasLimit, operator)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewCreateSnapshotTransaction -
func (nc *GlobalParam) NewCreateSnapshotTransaction(gasPrice, gasLimit uint64) (*types.MutableTransaction, error) {
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		GlobalParamsContractVersion,
		GlobalParamsContractAddress,
		global_params.CREATE_SNAPSHOT_NAME,
		[]interface{}{},
	)
}

// CreateSnapshot -
func (nc *GlobalParam) CreateSnapshot(gasPrice, gasLimit uint64, signer *Account) (common.Uint256, error) {
	tx, err := nc.NewCreateSnapshotTransaction(gasPrice, gasLimit)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// Auth -
type Auth struct {
	ontSdk *OntologySdk
	native *NativeContract
}

// NewAssignFuncsToRoleTransaction -
func (nc *Auth) NewAssignFuncsToRoleTransaction(gasPrice, gasLimit uint64, contractAddress common.Address, adminID, role []byte, funcNames []string, keyIndex int) (*types.MutableTransaction, error) {
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		AuthContractVersion,
		AuthContractAddress,
		"assignFuncsToRole",
		[]interface{}{
			contractAddress,
			adminID,
			role,
			funcNames,
			keyIndex,
		})
}

// AssignFuncsToRole -
func (nc *Auth) AssignFuncsToRole(gasPrice, gasLimit uint64, contractAddress common.Address, signer *Account, adminID, role []byte, funcNames []string, keyIndex int) (common.Uint256, error) {
	tx, err := nc.NewAssignFuncsToRoleTransaction(gasPrice, gasLimit, contractAddress, adminID, role, funcNames, keyIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewDelegateTransaction -
func (nc *Auth) NewDelegateTransaction(gasPrice, gasLimit uint64, contractAddress common.Address, from, to, role []byte, period, level, keyIndex int) (*types.MutableTransaction, error) {
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		AuthContractVersion,
		AuthContractAddress,
		"delegate",
		[]interface{}{
			contractAddress,
			from,
			to,
			role,
			period,
			level,
			keyIndex,
		})
}

// Delegate -
func (nc *Auth) Delegate(gasPrice, gasLimit uint64, signer *Account, contractAddress common.Address, from, to, role []byte, period, level, keyIndex int) (common.Uint256, error) {
	tx, err := nc.NewDelegateTransaction(gasPrice, gasLimit, contractAddress, from, to, role, period, level, keyIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewWithdrawTransaction -
func (nc *Auth) NewWithdrawTransaction(gasPrice, gasLimit uint64, contractAddress common.Address, initiator, delegate, role []byte, keyIndex int) (*types.MutableTransaction, error) {
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		AuthContractVersion,
		AuthContractAddress,
		"withdraw",
		[]interface{}{
			contractAddress,
			initiator,
			delegate,
			role,
			keyIndex,
		})
}

// Withdraw -
func (nc *Auth) Withdraw(gasPrice, gasLimit uint64, signer *Account, contractAddress common.Address, initiator, delegate, role []byte, keyIndex int) (common.Uint256, error) {
	tx, err := nc.NewWithdrawTransaction(gasPrice, gasLimit, contractAddress, initiator, delegate, role, keyIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewAssignOntIDsToRoleTransaction -
func (nc *Auth) NewAssignOntIDsToRoleTransaction(gasPrice, gasLimit uint64, contractAddress common.Address, admOntID, role []byte, persons [][]byte, keyIndex int) (*types.MutableTransaction, error) {
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		AuthContractVersion,
		AuthContractAddress,
		"assignOntIDsToRole",
		[]interface{}{
			contractAddress,
			admOntID,
			role,
			persons,
			keyIndex,
		})
}

// AssignOntIDsToRole -
func (nc *Auth) AssignOntIDsToRole(gasPrice, gasLimit uint64, signer *Account, contractAddress common.Address, admOntID, role []byte, persons [][]byte, keyIndex int) (common.Uint256, error) {
	tx, err := nc.NewAssignOntIDsToRoleTransaction(gasPrice, gasLimit, contractAddress, admOntID, role, persons, keyIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewTransferTransaction -
func (nc *Auth) NewTransferTransaction(gasPrice, gasLimit uint64, contractAddress common.Address, newAdminID []byte, keyIndex int) (*types.MutableTransaction, error) {
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		AuthContractVersion,
		AuthContractAddress,
		"transfer",
		[]interface{}{
			contractAddress,
			newAdminID,
			keyIndex,
		})
}

// Transfer -
func (nc *Auth) Transfer(gasPrice, gasLimit uint64, signer *Account, contractAddress common.Address, newAdminID []byte, keyIndex int) (common.Uint256, error) {
	tx, err := nc.NewTransferTransaction(gasPrice, gasLimit, contractAddress, newAdminID, keyIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}

// NewVerifyTokenTransaction -
func (nc *Auth) NewVerifyTokenTransaction(gasPrice, gasLimit uint64, contractAddress common.Address, caller []byte, funcName string, keyIndex int) (*types.MutableTransaction, error) {
	return nc.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		AuthContractVersion,
		AuthContractAddress,
		"verifyToken",
		[]interface{}{
			contractAddress,
			caller,
			funcName,
			keyIndex,
		})
}

// VerifyToken -
func (nc *Auth) VerifyToken(gasPrice, gasLimit uint64, signer *Account, contractAddress common.Address, caller []byte, funcName string, keyIndex int) (common.Uint256, error) {
	tx, err := nc.NewVerifyTokenTransaction(gasPrice, gasLimit, contractAddress, caller, funcName, keyIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = nc.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return nc.ontSdk.SendTransaction(tx)
}
