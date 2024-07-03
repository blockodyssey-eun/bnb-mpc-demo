package utils

import (
	"log"
	"math/big"
	"tss_demo/lib/eth"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func InjectTestEther(client *ethclient.Client, privateKey string, toAddress common.Address, amount *big.Int) {
	pk, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	signedTx, err := eth.SignTransactionWithPrivateKey(client, pk, toAddress, amount)
	if err != nil {
		log.Fatalf("failed to sign transaction: %v", err)
	}

	err = eth.SendSignedTransaction(client, signedTx, true)
	if err != nil {
		log.Fatalf("failed to send signed transaction: %v", err)
	}
}

