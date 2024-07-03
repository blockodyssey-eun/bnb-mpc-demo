package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"time"
	tss_ecdsa "tss_demo/lib/ecdsa"
	"tss_demo/lib/eth"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// parties 타입 정의
type parties []*tss_ecdsa.Party

// parties 초기화
func (parties parties) init(senders []tss_ecdsa.Sender) {
	for i, p := range parties {
		p.Init(parties.numericIDs(), len(parties)-1, senders[i])
	}
}

// party원들의 shares 데이터를 설정
func (parties parties) setShareData(shareData [][]byte) {
	for i, p := range parties {
		p.SetShareData(shareData[i])
	}
}

// 메시지 서명 함수
//
// 각 파티가 서명 작업을 병렬로 수행하며 결과를 수집.
// 오류가 발생하면 그 오류 반환.
func (parties parties) sign(msg []byte) ([][]byte, error) {
	var lock sync.Mutex
	var sigs [][]byte
	var threadSafeError atomic.Value

	var wg sync.WaitGroup
	wg.Add(len(parties))

	for _, p := range parties {
		go func(p *tss_ecdsa.Party) {
			defer wg.Done()
			sig, err := p.Sign(context.Background(), msg)
			if err != nil {
				threadSafeError.Store(err.Error())
				return
			}

			lock.Lock()
			sigs = append(sigs, sig)
			lock.Unlock()
		}(p)
	}

	wg.Wait()

	err := threadSafeError.Load()
	if err != nil {
		return nil, fmt.Errorf(err.(string))
	}

	return sigs, nil
}

// 키 생성 함수
//
// 각 파티가 키 생성 작업을 병렬로 수행하며 결과를 수집.
// 오류가 발생하면 그 오류를 반환.
func (parties parties) keygen() ([][]byte, error) {
	var lock sync.Mutex
	shares := make([][]byte, len(parties))
	var threadSafeError atomic.Value

	var wg sync.WaitGroup
	wg.Add(len(parties))

	for i, p := range parties {
		go func(p *tss_ecdsa.Party, i int) {
			defer wg.Done()
			share, err := p.KeyGen(context.Background())
			if err != nil {
				threadSafeError.Store(err.Error())
				return
			}

			lock.Lock()
			shares[i] = share
			lock.Unlock()
		}(p, i)
	}

	wg.Wait()

	err := threadSafeError.Load()
	if err != nil {
		return nil, fmt.Errorf(err.(string))
	}

	return shares, nil
}

// numeric IDs를 생성하는 함수
//
// 각 파티의 ID를 기반으로 uint16 타입의 ID 목록을 생성합니다.
func (parties parties) numericIDs() []uint16 {
	var res []uint16
	for _, p := range parties {
		res = append(res, uint16(big.NewInt(0).SetBytes(p.ID().Key).Uint64()))
	}

	return res
}

func senders(parties parties) []tss_ecdsa.Sender {
	var senders []tss_ecdsa.Sender
	for _, src := range parties {
		src := src
		sender := func(msgBytes []byte, broadcast bool, to uint16) {
			messageSource := uint16(big.NewInt(0).SetBytes(src.ID().Key).Uint64())
			if broadcast {
				for _, dst := range parties {
					if dst.ID() == src.ID() {
						continue
					}
					dst.OnMsg(msgBytes, messageSource, broadcast)
				}
			} else {
				for _, dst := range parties {
					if to != uint16(big.NewInt(0).SetBytes(dst.ID().Key).Uint64()) {
						continue
					}
					dst.OnMsg(msgBytes, messageSource, broadcast)
				}
			}
		}
		senders = append(senders, sender)
	}
	return senders
}

func loadENV() (string, string) {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	return os.Getenv("INFURA_KEY"), os.Getenv("PRIVATE_KEY")
}

func createAndInitializeParties(numParties int) parties {
	logger := func(id string) tss_ecdsa.Logger {
		logConfig := zap.NewDevelopmentConfig()
		logger, _ := logConfig.Build()
		logger = logger.With(zap.String("id", id))
		return logger.Sugar()
	}

	var parties parties
	for i := 1; i <= numParties; i++ {
		party := tss_ecdsa.NewParty(uint16(i), logger(fmt.Sprintf("p%d", i)))
		parties = append(parties, party)
	}

	parties.init(senders(parties))

	return parties
}

func main() {
	INFURA_KEY, _ := loadENV()

	infuraURL := fmt.Sprintf("https://sepolia.infura.io/v3/%s", INFURA_KEY)
	client, err := ethclient.Dial(infuraURL)
	if err != nil {
		log.Fatalf("failed to connect to the Ethereum client: %v", err)
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("chainID:", chainID)
	// Create and initialize parties
	numParties := 3
	parties := createAndInitializeParties(numParties)

	fmt.Println("Running DKG")

	// 키 생성
	t1 := time.Now()
	shares, _ := parties.keygen()
	fmt.Println("쉐어 키: \n", shares)
	for i, share := range shares {
		hexShare := bytesToHexString(share)
		fmt.Printf("파티 %d의 쉐어 키 (hex): %s\n", i+1, hexShare)
	}

	fmt.Printf("DKG elapsed %s\n", time.Since(t1))

	parties.init(senders(parties))

	// 공유 데이터 설정
	parties.setShareData(shares)

	// 기본 정보 추출 (퍼블릭키, 주소)
	pk, err := parties[0].TPubKey()
	assert.NoError(nil, err)

	public_key, address := eth.GetEthereumAddressByPk(pk)

	fmt.Println("퍼블릭키: \n", public_key)
	fmt.Println("주소: \n", address)

	// 테스트 이더 주입
	amount := big.NewInt(100000000000000) // 0.0001 Ether
	// utils.InjectTestEther(client, PRIVATE_KEY, common.HexToAddress(address), amount)

	// 서명되지 않은 트랜잭션 생성
	signer := types.NewEIP155Signer(chainID)
	// make raw tx
	tx, txHash := eth.GenerateRlpEncodedTx(
		*client,
		signer,
		common.HexToAddress(address),
		common.HexToAddress("0x1139F74a15f25f7503B30cd36D527DA5A6D3E15D"),
		new(big.Int).Div(amount, big.NewInt(3)),
	)
	fmt.Printf("unSigned TxHash: 0x%s\n", txHash)

	sigs, err := parties.sign(txHash)
	// fmt.Print("서명데이터:", sigs)
	assert.NoError(nil, err)
	fmt.Printf("Signing completed in %v\n", time.Since(t1))

	// 서명 검증
	sigSet := make(map[string]struct{})
	for _, s := range sigs {
		sigSet[string(s)] = struct{}{}
	}
	// Q: 개별 서명의 셋이 1이여야하는 이유가? 1)로컬 피어라서? 2)메시지 데이터를 다 넘겨서?
	assert.Len(nil, sigSet, 1)
	type EcdsaSignature struct {
		R, S *big.Int
	}
	sig := sigs[0]

	var signature EcdsaSignature

	_, err = asn1.Unmarshal(sig, &signature)
	if err != nil {
		fmt.Printf("ASN.1 디코딩 실패: %v\n", err)
		return
	}
	fmt.Printf("트랜잭션 해시: \n%s", txHash)
	fmt.Printf("서명 값:\nR: %s\nS: %s\n", signature.R.Text(16), signature.S.Text(16))
	signatureBytes := append(signature.R.Bytes(), signature.S.Bytes()...)

	verification_by_goethereum := crypto.VerifySignature(crypto.FromECDSAPub(pk), txHash, signatureBytes)
	fmt.Printf("Signature valid by goethereum: %t\n", verification_by_goethereum)
	// v := byte(27) // 기본값으로 27 설정

	// // EIP-155에 따른 V 값 조정
	// if chainID.Sign() != 0 {
	// 	v = byte(signature.R.Sign() + 35 + int(chainID.Uint64()*2))
	// } else {
	// 	v = byte(signature.R.Sign() + 27)
	// }
	var recid int64 = 0
	V := byte(big.NewInt(recid).Uint64())
	signatureBytes = append(signatureBytes, V)

	signedTx, err := tx.WithSignature(signer, signatureBytes)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}

	sender, err := types.Sender(signer, signedTx)
	if err != nil {
		log.Fatalf("Failed to recover sender: %v", err)
	}
	fmt.Printf("Recovered sender: %s\n", sender.Hex())
	fmt.Println("\nBefore signing:")
}

// keccak256 해싱
func digest(in []byte) []byte {
	return crypto.Keccak256(in)
}

func bytesToHexString(data []byte) string {
	return hex.EncodeToString(data)
}

func hexStringToBytes(hexStr string) ([]byte, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %v", err)
	}
	return bytes, nil
}

func recoverEthereumAddress(r, s *big.Int, msgHash []byte) (byte, common.Address, error) {
	for v := 27; v <= 28; v++ {
		sig := make([]byte, 65)
		copy(sig[0:32], r.Bytes())
		copy(sig[32:64], s.Bytes())
		sig[64] = byte(v)

		pubKey, err := secp256k1.RecoverPubkey(msgHash, sig)
		if err == nil {
			address := crypto.PubkeyToAddress(*toECDSAPub(pubKey))
			return byte(v), address, nil
		}
	}
	return 0, common.Address{}, fmt.Errorf("공개 키 복구 실패")
}

func toECDSAPub(pubKey []byte) *ecdsa.PublicKey {
	x := new(big.Int).SetBytes(pubKey[1:33])
	y := new(big.Int).SetBytes(pubKey[33:])
	return &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     x,
		Y:     y,
	}
}
