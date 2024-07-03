package eth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// 로우 트랜잭션 생성
func GenerateTransaction(nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *types.Transaction {
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    amount,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})
	return tx
}

// Private Key를 사용하여 트랜잭션 생성 및 서명 -> 서명 트랜잭션
func SignTransactionWithPrivateKey(client *ethclient.Client, privateKey *ecdsa.PrivateKey, toAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %v", err)
	}

	gasLimit := uint64(21000)
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get gas price: %v", err)
	}

	tx := GenerateTransaction(nonce, toAddress, amount, gasLimit, gasPrice, nil)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %v", err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}

	return signedTx, nil
}

// 서명 트랜잭션 브로드 케스트
func SendSignedTransaction(client *ethclient.Client, signedTx *types.Transaction, wait ...bool) error {
	// wait의 기본값을 false로 설정
	shouldWait := false
	if len(wait) > 0 {
		shouldWait = wait[0]
	}

	// 트랜잭션 전송
	err := client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %v", err)
	}

	fmt.Printf("Transaction sent: %s\n", signedTx.Hash().Hex())

	// 트랜잭션 완료를 기다릴지 결정
	if shouldWait {
		receipt, err := waitForTransaction(client, signedTx.Hash())
		if err != nil {
			return fmt.Errorf("error waiting for transaction: %v", err)
		}
		fmt.Printf("Transaction confirmed in block %d\n", receipt.BlockNumber.Uint64())
	}

	return nil
}

// 트랜잭션 완료를 기다리는 헬퍼 함수
func waitForTransaction(client *ethclient.Client, txHash common.Hash) (*types.Receipt, error) {
	for {
		receipt, err := client.TransactionReceipt(context.Background(), txHash)
		if err != nil {
			if err == ethereum.NotFound {
				time.Sleep(time.Second) // 1초 대기 후 다시 시도
				continue
			}
			return nil, err
		}
		return receipt, nil
	}
}

// 트랜잭션 RLP 인코딩
func EncodeTransactionRLP(tx *types.Transaction) ([]byte, error) {
	var buf bytes.Buffer
	err := tx.EncodeRLP(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// 이더리움 공개키 및 주소
func GetEthereumAddressByPk(pk *ecdsa.PublicKey) (string, string) {
	pk_bytes := crypto.FromECDSAPub(pk)
	pk_hex := hexutil.Encode(pk_bytes)
	address := crypto.PubkeyToAddress(*pk).Hex()
	return pk_hex, address
}

func GenerateRlpEncodedTx(client ethclient.Client, signer types.Signer, fromAddress common.Address, toAddress common.Address, amount *big.Int) (*types.Transaction, []byte) {
	// sign
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatalf("failed to get nonce: %v", err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("failed to get gas price: %v", err)
	}

	gasLimit := uint64(21000)
	tx := GenerateTransaction(nonce, toAddress, amount, gasLimit, gasPrice, nil)
	txHash := signer.Hash(tx).Bytes()
	return tx, txHash
}
