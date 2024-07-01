package main

import (
	"context"
	"crypto/ecdsa"
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
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
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

func injectTestEther(client *ethclient.Client, privateKey *ecdsa.PrivateKey, toAddress common.Address, amount *big.Int) {
	signedTx, err := eth.SignTransactionWithPrivateKey(client, privateKey, toAddress, amount)
	if err != nil {
		log.Fatalf("failed to sign transaction: %v", err)
	}

	err = eth.SendSignedTransaction(client, signedTx)
	if err != nil {
		log.Fatalf("failed to send signed transaction: %v", err)
	}
}

func main() {
	INFURA_KEY, PRIVATE_KEY := loadENV()

	infuraURL := fmt.Sprintf("https://sepolia.infura.io/v3/%s", INFURA_KEY)
	client, err := ethclient.Dial(infuraURL)
	if err != nil {
		log.Fatalf("failed to connect to the Ethereum client: %v", err)
	}

	// Create and initialize parties
	numParties := 3
	parties := createAndInitializeParties(numParties)

	fmt.Println("Running DKG")

	// 키 생성
	t1 := time.Now()
	shares, _ := parties.keygen()
	fmt.Println("쉐어 키: \n", shares)

	// assert.NoError(nil, err)
	fmt.Printf("DKG elapsed %s\n", time.Since(t1))

	parties.init(senders(parties))

	// 공유 데이터 설정
	parties.setShareData(shares)

	// 기본 정보 추출 (퍼블릭키, 주소)
	pk, err := parties[0].TPubKey()
	assert.NoError(nil, err)

	public_key, address := getEthereumPublickeyAndAddress(pk)

	fmt.Println("퍼블릭키: \n", public_key)
	fmt.Println("주소: \n", address)

	// 테스트 이더 주입
	privateKey, err := crypto.HexToECDSA(PRIVATE_KEY)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}
	testAmount := big.NewInt(100000000000000) // 0.0001 Ether

	injectTestEther(client, privateKey, common.HexToAddress(address), testAmount)

	// 서명되지 않은 트랜잭션 생성
	nonce, err := client.PendingNonceAt(context.Background(), common.HexToAddress(address))
	if err != nil {
		log.Fatalf("failed to get nonce: %v", err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("failed to get gas price: %v", err)
	}

	gasLimit := uint64(21000)

	tx := eth.GenerateTransaction(nonce, common.HexToAddress("0x1139F74a15f25f7503B30cd36D527DA5A6D3E15D"), testAmount, gasLimit, gasPrice, nil)
	encoded_tx_rlp, err := eth.EncodeTransactionRLP(tx)
	if err != nil {
		log.Fatalf("failed to RLP encode transaction: %v", err)
	}

	print(encoded_tx_rlp)
	// 메시지 서명
	msgToSign := encoded_tx_rlp

	fmt.Println("Signing message")
	t1 = time.Now()
	sigs, err := parties.sign(digest(msgToSign))
	fmt.Print("서명데이터:", sigs)
	assert.NoError(nil, err)
	fmt.Printf("Signing completed in %v\n", time.Since(t1))

	// 서명 검증
	sigSet := make(map[string]struct{})
	for _, s := range sigs {
		sigSet[string(s)] = struct{}{}
	}
	assert.Len(nil, sigSet, 1)
	sig := sigs[0]
	sig = append(sig, byte(27)) // 'v' 값 추가

	// verification := crypto.VerifySignature(crypto.FromECDSAPub(pk), digest(msgToSign), sig)
	verification := ecdsa.VerifyASN1(pk, digest(msgToSign), sigs[0])
	fmt.Printf("Signature valid: %t\n", verification)

}

// digest function as defined in ecdsa package
func digest(in []byte) []byte {
	return crypto.Keccak256(in)
}

// 이더리움 공개키 및 주소
func getEthereumPublickeyAndAddress(pk *ecdsa.PublicKey) (string, string) {
	pk_bytes := crypto.FromECDSAPub(pk)
	pk_hex := hexutil.Encode(pk_bytes)
	address := crypto.PubkeyToAddress(*pk).Hex()
	return pk_hex, address
}
