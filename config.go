package ontchain

import (
	sdk "github.com/vinely/ontchain/ontsdk"
)

var (
	ontSdk *sdk.OntologySdk
	// Endpoint - ont block chain restful api endpoint
	Endpoint = "http://localhost:20334"
)

// GetSdk - get default sdk
// url - restful interface. If pass "" we using the default URL configurated.
func GetSdk(url string) *sdk.OntologySdk {
	if url == "" {
		url = Endpoint
	}
	if ontSdk != nil {
		return ontSdk
	}
	ontSdk = sdk.NewOntologySdk()
	ontSdk.NewRestClient().SetAddress(url)
	return ontSdk
}
